# frozen_string_literal: true

# Standalone error and value classes for PUN impersonation operations.
#
# These classes were extracted from the Admin API sessions controller
# to be reusable across services and controllers.

# Error class for impersonation failures.
#
# Carries a machine-readable error code and an HTTP status symbol so that
# controllers can render appropriate error responses.
#
# @example
#   raise ImpersonationError.new('USER_NOT_FOUND', 'User not found: bob', :not_found)
class ImpersonationError < StandardError
  attr_reader :code, :http_status

  # @param code [String] Machine-readable error code (e.g., 'IMPERSONATION_FAILED')
  # @param message [String] Human-readable error message
  # @param http_status [Symbol] Rails HTTP status symbol (e.g., :bad_gateway)
  def initialize(code, message, http_status = :bad_gateway)
    @code = code
    @http_status = http_status
    super(message)
  end
end

# Value object wrapping session data returned from impersonation responses.
#
# When a session is created via impersonation (through the internal API),
# the response is a JSON hash rather than a BatchConnect::Session object.
# This class provides a compatible interface for the controller.
class ImpersonatedSession
  attr_reader :id, :job_id, :created_at, :user, :session_url

  # @param data [Hash] Parsed JSON response from internal API
  def initialize(data)
    @id = data['id'] || data['session_id']
    @job_id = data['job_id']
    @created_at = data['created_at']
    @user = data['user']
    @session_url = data['session_url']
  end

  # Compatibility with BatchConnect::Session interface
  # @return [String] Session UUID
  def session_id
    @id
  end
end
