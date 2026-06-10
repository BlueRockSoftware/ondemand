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
  # No sub was supplied and the (optional) Keycloak email->sub lookup is not
  # configured, so the caller MUST provide the raw sub. A client-input error,
  # surfaced as 400 (not 422) -- the request is missing required input.
  class SubRequiredError < ProvisionError; end

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
      raise SubRequiredError,
            "sub is required: supply the user's raw Keycloak sub. (The email " \
            'fallback needs the Keycloak admin lookup, which is not configured.)'
    rescue KeycloakAdminClient::Error => e
      Rails.logger.error("UserProvisioner: Keycloak lookup failed for #{preferred_username}: #{e.message}")
      raise ProvisionError, "Keycloak lookup failed for '#{preferred_username}'"
    end

    # LDAP/k8s env user_map.py (via ldap_ops.py / create_k8s_account.py) needs.
    # On the Apache login path these are inherited from the container env; in the
    # admin PUN the env is scrubbed, so we forward them explicitly into the
    # mapper's invocation. They are read here from the bare name or its OOD_
    # alias (the only form that survives the PUN's OOD_*-only passthrough), and
    # passed as BARE names so sudo's env_keep (LDAP_*/KUBERNETES_*) preserves
    # them and ldap_ops.py reads them directly.
    FORWARDED_ENV = %w[
      LDAP_URI LDAP_BIND_DN LDAP_BIND_PW LDAP_BASE_DN
      KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT
    ].freeze

    def run_user_map(oidc_sub, preferred_username)
      env = subprocess_env(oidc_sub)
      stdout, stderr, status = Open3.capture3(env, *USER_MAP_CMD, preferred_username)
      username = stdout.to_s.strip.lines.last&.strip
      unless status.success? && !username.to_s.empty?
        detail = stderr.to_s.strip.lines.last(3).join(' ').strip
        Rails.logger.error(
          "UserProvisioner: user_map.py failed for #{preferred_username} " \
          "(exit=#{status.exitstatus}): #{detail}"
        )
        # Surface the mapper's own error so the API response is self-diagnosing.
        msg = "Failed to provision user '#{preferred_username}'"
        msg += ": #{detail}" unless detail.empty?
        raise ProvisionError, msg
      end
      username
    rescue ProvisionError
      raise
    rescue StandardError => e
      Rails.logger.error("UserProvisioner: unexpected error provisioning #{preferred_username}: #{e.message}")
      raise ProvisionError, "Failed to provision user '#{preferred_username}'"
    end

    # OIDC_SUB plus the forwarded LDAP/k8s vars (bare name or OOD_ alias).
    def subprocess_env(oidc_sub)
      env = { 'OIDC_SUB' => oidc_sub }
      FORWARDED_ENV.each do |name|
        value = ENV[name] || ENV["OOD_#{name}"]
        env[name] = value unless value.to_s.empty?
      end
      if env['LDAP_BIND_PW'].to_s.empty? || env['LDAP_URI'].to_s.empty?
        raise ProvisionError,
              'LDAP credentials are not available in the provisioning context ' \
              '(neither LDAP_* nor OOD_LDAP_* is set on the dashboard PUN). ' \
              'Check the OOD chart deployment env and pun_custom_env_declarations.'
      end
      env
    end
  end
end
