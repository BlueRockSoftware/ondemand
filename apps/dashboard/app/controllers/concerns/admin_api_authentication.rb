# frozen_string_literal: true

# Shared Bearer-token authentication for the admin API controllers.
#
# Extracted from Api::V1::BatchConnect::SessionsController so that every admin
# API endpoint (sessions, user provisioning, ...) authenticates identically.
# Include the concern and declare `before_action :authenticate_admin_api_request`.
module AdminApiAuthentication
  extend ActiveSupport::Concern

  private

  # Authenticate an admin API request via the Authorization: Bearer header.
  # Renders 401 and halts the filter chain when the token is missing/invalid.
  def authenticate_admin_api_request
    auth_header = request.headers['Authorization']

    unless auth_header&.start_with?('Bearer ')
      Rails.logger.warn("Admin API: No Authorization header from #{request.remote_ip}")
      return render json: {
        status: 'error',
        message: 'Authentication required. Provide Bearer token.'
      }, status: :unauthorized
    end

    token = auth_header.split(' ').last

    unless validate_admin_token(token)
      Rails.logger.warn("Admin API: Invalid admin token from #{request.remote_ip}")
      return render json: {
        status: 'error',
        message: 'Invalid or unauthorized API token'
      }, status: :unauthorized
    end

    Rails.logger.debug('Admin API: Authenticated with admin token')
    true
  end

  # Validate an admin token.
  # TODO: Implement proper token validation with database storage
  #   (accept tokens by prefix only for now; in production validate against
  #   stored admin tokens, check expiration, etc.)
  def validate_admin_token(token)
    token.start_with?('ood-api-admin-')
  end
end
