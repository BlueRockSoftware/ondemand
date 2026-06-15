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

  # Validate an admin token against the deployment's configured secret.
  #
  # The token is the generated OOD_INTERNAL_API_TOKEN (minted with the
  # `ood-api-admin-` prefix by the chart's ood-internal-token Secret and
  # injected into the PUN env via pun_custom_env_declarations). We compare the
  # FULL value, not just the prefix — the prefix is public, so a prefix-only
  # check accepts any caller. Fails closed when no secret is configured, and
  # uses a constant-time comparison to avoid leaking the token via timing.
  def validate_admin_token(token)
    expected = ENV['OOD_INTERNAL_API_TOKEN'].to_s
    return false if expected.empty?
    return false unless token.to_s.start_with?('ood-api-admin-')

    ActiveSupport::SecurityUtils.secure_compare(token.to_s, expected)
  end
end
