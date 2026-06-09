# frozen_string_literal: true

require 'open3'
require_relative 'dex_subject'
require_relative 'keycloak_admin_client'

# Resolve-or-create a local system identity for an OIDC user.
#
# This is the programmatic entrypoint to the same identity logic the
# interactive login uses: it shells to /opt/ood/user_map.py (as root via the
# www-data sudoers rule), passing the OIDC sub as OIDC_SUB and the email-like
# preferred_username as argv. user_map.py searches LDAP by employeeNumber (sub),
# lazily migrates, or creates a new posixAccount + home + k8s account, then
# prints the canonical local username.
#
# Identity key: OOD authenticates through Dex, so the sub stored in LDAP is the
# Dex-encoded subject, NOT the raw upstream (Keycloak) sub. Callers such as the
# test-app talk to Keycloak directly and only have the RAW sub. We therefore
# re-encode the raw sub into Dex's subject format (see DexSubject) before
# handing it to user_map.py, so API-provisioned users resolve to the SAME
# identity an interactive OOD/Dex login would -- no duplicate accounts.
#
# Callers MUST use the returned username rather than deriving one from the email
# themselves: collision handling and stable-identity resolution can produce a
# username a naive email transform would not (see
# docs/features/stable-user-identity.md).
class UserProvisioner
  # user_map.lua invokes the mapper this exact way; reuse it so the API and
  # login paths resolve identically. www-data may run it NOPASSWD (ood-sudoers),
  # and env_keep preserves OIDC_SUB / LDAP_* / KUBERNETES_* through sudo.
  USER_MAP_CMD = ['sudo', '/opt/ood/user_map.py'].freeze

  # Dex connector id whose subject namespace OOD stores. Matches the connector
  # `id:` in dex-values.yaml. Overridable for non-default deployments.
  DEFAULT_CONNECTOR_ID = 'keycloak'

  # Raw subs are UUIDs; preferred_username is email-like. Validate before
  # spawning so a malformed identity fails fast. (The Open3 array form already
  # prevents shell injection regardless.)
  SUB_PATTERN = /\A[a-zA-Z0-9._:-]{1,255}\z/.freeze
  PREFERRED_USERNAME_PATTERN = /\A[a-zA-Z0-9._%+@-]{1,255}\z/.freeze

  class ProvisionError < StandardError; end
  # The email has no matching user in the upstream IdP (so no sub to key on).
  class UserNotFoundError < ProvisionError; end

  class << self
    # Provision by raw sub (preferred) or, when sub is blank, by email lookup.
    #
    # @param preferred_username [String] email-like preferred_username claim
    # @param sub [String, nil] raw upstream (Keycloak) subject; if blank, it is
    #   looked up from Keycloak by preferred_username
    # @param connector_id [String] Dex connector id (defaults to env/keycloak)
    # @return [String] canonical local username (e.g. "casmith_jcvi")
    # @raise [UserNotFoundError] if sub is blank and no Keycloak user matches
    # @raise [ProvisionError] on invalid input, missing Keycloak config, or
    #   mapper failure
    def call(preferred_username:, sub: nil, connector_id: nil)
      preferred_username = preferred_username.to_s.strip
      raise ProvisionError, 'preferred_username is required' if preferred_username.empty?
      unless PREFERRED_USERNAME_PATTERN.match?(preferred_username)
        raise ProvisionError, 'preferred_username is malformed'
      end

      raw_sub = resolve_raw_sub(sub, preferred_username)
      connector_id = (connector_id || ENV['DEX_CONNECTOR_ID'] || DEFAULT_CONNECTOR_ID).to_s

      # Match the sub Dex would have issued for this identity.
      oidc_sub = DexSubject.encode(raw_sub, connector_id)

      username = run_user_map(oidc_sub, preferred_username)
      Rails.logger.info("UserProvisioner: provisioned '#{preferred_username}' => '#{username}'")
      username
    end

    private

    # Return a validated raw upstream sub, looking it up by email when not given.
    def resolve_raw_sub(sub, preferred_username)
      sub = sub.to_s.strip
      if sub.empty?
        sub = lookup_sub_by_email(preferred_username)
      end
      raise ProvisionError, 'sub is malformed' unless SUB_PATTERN.match?(sub)

      sub
    end

    def lookup_sub_by_email(preferred_username)
      sub = KeycloakAdminClient.lookup_sub_by_email(preferred_username)
      if sub.to_s.strip.empty?
        raise UserNotFoundError, "No Keycloak user found for '#{preferred_username}'"
      end

      sub
    rescue KeycloakAdminClient::NotConfiguredError
      raise ProvisionError,
            'No sub supplied and Keycloak admin lookup is not configured; ' \
            'provide the OIDC sub or configure KEYCLOAK_ADMIN_* on the OOD pod.'
    rescue KeycloakAdminClient::Error => e
      Rails.logger.error("UserProvisioner: Keycloak lookup failed for #{preferred_username}: #{e.message}")
      raise ProvisionError, "Keycloak lookup failed for '#{preferred_username}'"
    end

    def run_user_map(oidc_sub, preferred_username)
      stdout, stderr, status = Open3.capture3(
        { 'OIDC_SUB' => oidc_sub },
        *USER_MAP_CMD,
        preferred_username
      )
      username = stdout.to_s.strip.lines.last&.strip
      unless status.success? && !username.to_s.empty?
        Rails.logger.error(
          "UserProvisioner: user_map.py failed for #{preferred_username} " \
          "(exit=#{status.exitstatus}): #{stderr.to_s.strip}"
        )
        raise ProvisionError, "Failed to provision user '#{preferred_username}'"
      end
      username
    rescue ProvisionError
      raise
    rescue StandardError => e
      Rails.logger.error("UserProvisioner: unexpected error provisioning #{preferred_username}: #{e.message}")
      raise ProvisionError, "Failed to provision user '#{preferred_username}'"
    end
  end
end
