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
      # Body: { "preferred_username": "user@domain.org", "sub": "<keycloak-uuid>" }
      #   - sub is the RAW upstream (Keycloak) subject; the caller has it from the
      #     user's Keycloak session (e.g. the test-app forwards it).
      #   - sub is REQUIRED unless the optional Keycloak email->sub lookup is
      #     configured (KEYCLOAK_ADMIN_* on the OOD pod). With the lookup off,
      #     a missing sub returns 400 SUB_REQUIRED; with it on, sub may be omitted
      #     and is resolved from Keycloak by email.
      # Returns: { "status": "success", "username": "user_domain" }
      def provision
        preferred_username = params.require(:preferred_username)
        sub = params[:sub]

        username = UserProvisioner.call(preferred_username: preferred_username, sub: sub)

        render json: { status: 'success', username: username }, status: :ok
      rescue ActionController::ParameterMissing => e
        render json: {
          status: 'error',
          message: "Missing required parameter: #{e.param}"
        }, status: :bad_request
      rescue UserProvisioner::SubRequiredError => e
        # Must precede the ProvisionError rescue (SubRequiredError subclasses it).
        render json: {
          status: 'error',
          code: 'SUB_REQUIRED',
          message: e.message
        }, status: :bad_request
      rescue UserProvisioner::UserNotFoundError => e
        render json: {
          status: 'error',
          code: 'USER_NOT_FOUND',
          message: e.message
        }, status: :not_found
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
