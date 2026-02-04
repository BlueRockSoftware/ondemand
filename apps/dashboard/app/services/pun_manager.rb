# frozen_string_literal: true

require 'etc'

# Configuration and validation for PUN (Per-User Nginx) impersonation
#
# This service provides configuration methods for Apache-mediated user
# impersonation. PUN lifecycle management (starting, monitoring) is handled
# by Apache's pun_proxy.lua, not by this service.
#
# The Apache-mediated approach:
# 1. Admin API makes HTTP request to Apache with X-Impersonate-User header
# 2. api_auth.lua validates the internal token and sets REMOTE_USER
# 3. pun_proxy.lua starts the target user's PUN if needed (via nginx_stage)
# 4. Request is forwarded to target user's PUN
#
# This approach uses Apache's existing sudo permissions (www-data) instead of
# requiring all users to have sudo access.
class PunManager
  # Custom errors
  class PunError < StandardError; end
  class UserNotFoundError < PunError; end

  class << self
    # Validate that a user exists in the system (LDAP/NSS)
    #
    # This check is done before forwarding to Apache to provide
    # early error detection with a clear error message.
    #
    # @param username [String] System username
    # @return [Struct::Passwd] User's passwd entry
    # @raise [UserNotFoundError] if user doesn't exist
    def validate_user(username)
      Etc.getpwnam(username)
    rescue ArgumentError
      raise UserNotFoundError, "User not found: #{username}"
    end

    # Check if impersonation is enabled
    #
    # When enabled, the Admin API will forward requests through Apache
    # to create sessions in the target user's PUN context.
    #
    # @return [Boolean] true if impersonation is enabled
    def impersonation_enabled?
      ENV.fetch('OOD_IMPERSONATION_ENABLED', 'true').downcase == 'true'
    end

    # Get the internal API token
    #
    # This token is used to authenticate impersonation requests between
    # the Admin API (in the admin user's PUN) and Apache's api_auth.lua.
    #
    # @return [String, nil] Internal API token or nil if not set
    def internal_api_token
      ENV['OOD_INTERNAL_API_TOKEN']
    end
  end
end
