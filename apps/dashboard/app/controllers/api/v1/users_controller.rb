# frozen_string_literal: true

require_relative '../../../services/user_provisioner'

module Api
  module V1
    # Admin API controller for user lifecycle operations.
    #
    # Provisioning is idempotent: it resolves a returning user by their
    # immutable OIDC sub or creates the LDAP/home/k8s account on first sight.
    # Clients call this BEFORE any session-create or Volume API request so the
    # target user reliably resolves via NSS (avoiding the "User not found" /
    # "Cannot resolve user" failures that occur when a user has only ever
    # authenticated to a downstream app and never completed an OOD login).
    class UsersController < ApplicationController
      include AdminApiAuthentication

      # API clients (no browser session / CSRF token).
      skip_before_action :verify_authenticity_token
      before_action :authenticate_admin_api_request

      # POST /api/v1/users/provision
      # Body: { "sub": "<keycloak-uuid>", "preferred_username": "user@domain.org" }
      # Returns: { "status": "success", "username": "user_domain" }
      def provision
        sub = params.require(:sub)
        preferred_username = params.require(:preferred_username)

        username = UserProvisioner.call(sub: sub, preferred_username: preferred_username)

        render json: { status: 'success', username: username }, status: :ok
      rescue ActionController::ParameterMissing => e
        render json: {
          status: 'error',
          message: "Missing required parameter: #{e.param}"
        }, status: :bad_request
      rescue UserProvisioner::ProvisionError => e
        render json: {
          status: 'error',
          code: 'PROVISION_FAILED',
          message: e.message
        }, status: :unprocessable_entity
      end
    end
  end
end
