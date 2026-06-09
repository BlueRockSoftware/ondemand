# frozen_string_literal: true

require 'open3'

# Resolve-or-create a local system identity for an authenticated OIDC user.
#
# This is the programmatic entrypoint to the same identity logic the
# interactive login uses: it shells to /opt/ood/user_map.py (as root via the
# www-data sudoers rule), passing the immutable Keycloak `sub` as OIDC_SUB and
# the email-like preferred_username as argv. user_map.py searches LDAP by
# employeeNumber (sub), lazily migrates, or creates a new posixAccount + home +
# k8s account, then prints the canonical local username.
#
# Callers (e.g. the test-app, ahead of a Volume API / session-create request)
# MUST use the returned username rather than deriving one from the email
# themselves: collision handling and stable-identity resolution can produce a
# username that a naive email transform would not (see
# docs/features/stable-user-identity.md).
class UserProvisioner
  # user_map.lua invokes the mapper this exact way; reuse it so the API and
  # login paths resolve identically. www-data may run it NOPASSWD (ood-sudoers),
  # and env_keep preserves OIDC_SUB / LDAP_* / KUBERNETES_* through sudo.
  USER_MAP_CMD = ['sudo', '/opt/ood/user_map.py'].freeze

  # Keycloak subs are UUIDs; preferred_username is email-like. Validate before
  # spawning so a malformed identity fails fast with a clear message. (The
  # Open3 array form already prevents shell injection regardless.)
  SUB_PATTERN = /\A[a-zA-Z0-9._:-]{1,255}\z/.freeze
  PREFERRED_USERNAME_PATTERN = /\A[a-zA-Z0-9._%+@-]{1,255}\z/.freeze

  class ProvisionError < StandardError; end

  class << self
    # @param sub [String] immutable OIDC subject claim (Keycloak UUID)
    # @param preferred_username [String] email-like preferred_username claim
    # @return [String] canonical local username (e.g. "casmith_jcvi")
    # @raise [ProvisionError] on invalid input or mapper failure
    def call(sub:, preferred_username:)
      sub = sub.to_s.strip
      preferred_username = preferred_username.to_s.strip

      raise ProvisionError, 'sub is required' if sub.empty?
      raise ProvisionError, 'preferred_username is required' if preferred_username.empty?
      raise ProvisionError, 'sub is malformed' unless SUB_PATTERN.match?(sub)
      raise ProvisionError, 'preferred_username is malformed' unless PREFERRED_USERNAME_PATTERN.match?(preferred_username)

      stdout, stderr, status = Open3.capture3(
        { 'OIDC_SUB' => sub },
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

      Rails.logger.info("UserProvisioner: provisioned '#{preferred_username}' => '#{username}'")
      username
    rescue ProvisionError
      raise
    rescue StandardError => e
      Rails.logger.error("UserProvisioner: unexpected error provisioning #{preferred_username}: #{e.message}")
      raise ProvisionError, "Failed to provision user '#{preferred_username}'"
    end
  end
end
