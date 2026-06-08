# frozen_string_literal: true

# Error class for PUN impersonation operations.
#
# Extracted from the Admin API sessions controller to be reusable across
# services and controllers.
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
