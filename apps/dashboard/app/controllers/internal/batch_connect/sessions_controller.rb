# frozen_string_literal: true

# Internal API Controller for batch connect session creation
# Used for PUN-to-PUN communication during user impersonation
#
# Security:
# - Only accessible from localhost (127.0.0.1 or ::1)
# - Requires X-Internal-Token header with valid token

module Internal
  module BatchConnect
    class SessionsController < ApplicationController
      # Skip CSRF verification for API calls
      skip_before_action :verify_authenticity_token

      # Verify internal access before all actions
      before_action :verify_internal_access
      before_action :verify_internal_token

      # Ensure all errors return JSON (avoid HTML 500 page so Admin API can parse response)
      rescue_from StandardError do |e|
        Rails.logger.error("Internal API: Unhandled error: #{e.class} - #{e.message}")
        Rails.logger.error(e.backtrace.first(15).join("\n"))
        render json: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          message: e.message
        }, status: :internal_server_error
      end

      # GET /internal/batch_connect/sessions
      # List sessions for the current PUN user
      #
      # This endpoint is called by the Admin API during impersonation.
      # Returns all sessions belonging to the PUN user.
      def index
        current_user = OodSupport::User.new

        Rails.logger.info("Internal API: Listing sessions for PUN user #{current_user.name}")

        sessions = ::BatchConnect::Session.all.map do |session|
          user_context = session.user_context rescue {}
          {
            id: session.id,
            user: current_user.name,
            job_id: session.job_id,
            title: session.title,
            status: session_status(session),
            created_at: session.created_at,
            cluster_id: session.cluster_id,
            token: session.token,
            project: user_context['project']
          }
        end

        render json: {
          status: 'success',
          sessions: sessions,
          user: current_user.name
        }

      rescue StandardError => e
        Rails.logger.error("Internal API: Error listing sessions: #{e.class} - #{e.message}")
        render json: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          message: e.message
        }, status: :internal_server_error
      end

      # POST /internal/batch_connect/sessions
      # Create a session in the context of the current PUN user
      #
      # This endpoint is called by the Admin API during impersonation.
      # The session is created for whoever's PUN is handling this request.
      #
      # Required body parameters:
      #   - app_token: batch connect app (e.g., "sys/bc_jupyter")
      #   - context: form parameters for the app
      #
      # Optional body parameters:
      #   - storage_path: relative NFS path for volume mount
      #   - volume_session_id: Volume API session ID for webhook linkage
      def create
        app_token = params.require(:app_token)
        context_params = params.require(:context).permit!.to_hash

        # Get current user (from PUN context)
        current_user = OodSupport::User.new

        Rails.logger.info("Internal API: Creating session for PUN user #{current_user.name}")

        # Load the batch connect app
        app = ::BatchConnect::App.from_token(app_token)
        unless app && app.valid?
          return render json: {
            status: 'error',
            code: 'APP_NOT_FOUND',
            message: "Batch connect app not found: #{app_token}"
          }, status: :not_found
        end

        # Build session context
        context = app.build_session_context
        context.attributes = context_params

        # Add volume integration parameters if provided
        storage_path = params[:storage_path]
        volume_session_id = params[:volume_session_id]
        if storage_path.present? || volume_session_id.present?
          context_params['storage_path'] = storage_path if storage_path.present?
          context_params['volume_session_id'] = volume_session_id if volume_session_id.present?
          context_params['nfs_base'] = ENV['NFS_BASE'] if ENV['NFS_BASE'].present?
          context_params['project_mount_path'] = ENV['PROJECT_MOUNT_PATH'] || '/mnt/project'
          context.attributes = context_params
        end

        unless context.valid?
          return render json: {
            status: 'error',
            code: 'INVALID_CONTEXT',
            message: 'Invalid context parameters',
            errors: context.errors.full_messages
          }, status: :unprocessable_entity
        end

        # Create session using standard BatchConnect flow
        session = ::BatchConnect::Session.new
        save_result = session.save(app: app, context: context)

        unless save_result
          detail = session.errors.full_messages.join('; ')
          Rails.logger.error("Internal API: Session save failed for #{current_user.name}: #{detail}")
          return render json: {
            status: 'error',
            code: 'SESSION_CREATE_FAILED',
            message: 'Failed to create session',
            errors: session.errors.full_messages
          }, status: :internal_server_error
        end

        Rails.logger.info("Internal API: Created session #{session.id} for #{current_user.name}")

        render json: {
          status: 'success',
          id: session.id,
          session_id: session.id,
          user: current_user.name,
          job_id: session.job_id,
          created_at: session.created_at,
          session_url: "/batch_connect/sessions/#{session.id}"
        }, status: :created

      rescue ActionController::ParameterMissing => e
        render json: {
          status: 'error',
          code: 'MISSING_PARAMETER',
          message: "Missing required parameter: #{e.param}"
        }, status: :bad_request

      rescue StandardError => e
        Rails.logger.error("Internal API: Error creating session: #{e.class} - #{e.message}")
        Rails.logger.error("Internal API: Backtrace: #{e.backtrace.join("\n")}")

        render json: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          message: e.message
        }, status: :internal_server_error
      end

      # GET /internal/batch_connect/sessions/:id
      # Get session details including connection info for the current PUN user
      #
      # This endpoint is called by the Admin API during impersonation to get
      # connection info for a session owned by the PUN user.
      def show
        session_id = params[:id]
        current_user = OodSupport::User.new

        Rails.logger.info("Internal API: Getting session #{session_id} for PUN user #{current_user.name}")

        session = find_owned_session(session_id)

        unless session
          return render json: {
            status: 'error',
            code: 'SESSION_NOT_FOUND',
            message: "Session not found: #{session_id}"
          }, status: :not_found
        end

        session_state = session_status(session)
        user_context = session.user_context rescue {}

        session_info = session.info.to_h rescue {}
        vol_session_id = session_info[:volume_session_id] || session_info['volume_session_id']

        session_hash = {
          id: session.id,
          user: current_user.name,
          job_id: session.job_id,
          title: session.title,
          status: session_state,
          created_at: session.created_at,
          cluster_id: session.cluster_id,
          token: session.token,
          info: session_info,
          project: user_context['project']
        }
        session_hash[:volume_session_id] = vol_session_id if vol_session_id.present?

        response_data = {
          status: 'success',
          session: session_hash
        }

        # Include connection info if session is running
        if session.running?
          begin
            connection_info = session.connect.to_h
            connection_url = build_connection_url(connection_info)
            response_data[:connection] = connection_info
            response_data[:connection_url] = connection_url
          rescue StandardError => e
            Rails.logger.warn("Internal API: Error getting connection info: #{e.message}")
          end
        end

        Rails.logger.info("Internal API: Retrieved session #{session_id} (status: #{session_state})")
        render json: response_data
      end

      # DELETE /internal/batch_connect/sessions/:id
      # Delete a session in the context of the current PUN user
      def destroy
        session_id = params[:id]
        current_user = OodSupport::User.new

        Rails.logger.info("Internal API: Deleting session #{session_id} for PUN user #{current_user.name}")

        session = find_owned_session(session_id)

        unless session
          return render json: {
            status: 'error',
            code: 'SESSION_NOT_FOUND',
            message: "Session not found: #{session_id}"
          }, status: :not_found
        end

        begin
          session.destroy
          Rails.logger.info("Internal API: Deleted session #{session_id}")

          render json: {
            status: 'success',
            message: 'Session deleted',
            user: current_user.name
          }
        rescue StandardError => e
          Rails.logger.error("Internal API: Error deleting session: #{e.class} - #{e.message}")
          render json: {
            status: 'error',
            code: 'DELETE_FAILED',
            message: e.message
          }, status: :internal_server_error
        end
      end

      private

      # Verify request is from localhost
      def verify_internal_access
        remote_ip = request.remote_ip

        unless remote_ip == '127.0.0.1' || remote_ip == '::1'
          Rails.logger.warn("Internal API: Access denied from #{remote_ip}")
          render json: {
            status: 'error',
            code: 'INTERNAL_ACCESS_DENIED',
            message: 'Internal API only accessible from localhost'
          }, status: :forbidden
        end
      end

      # Verify internal API token
      def verify_internal_token
        token = request.headers['X-Internal-Token']
        expected_token = PunManager.internal_api_token

        if expected_token.blank?
          Rails.logger.warn("Internal API: No internal token configured")
          return render json: {
            status: 'error',
            code: 'INTERNAL_AUTH_FAILED',
            message: 'Internal API token not configured'
          }, status: :forbidden
        end

        unless ActiveSupport::SecurityUtils.secure_compare(token.to_s, expected_token)
          Rails.logger.warn("Internal API: Invalid token provided")
          render json: {
            status: 'error',
            code: 'INTERNAL_AUTH_FAILED',
            message: 'Invalid internal API token'
          }, status: :forbidden
        end
      end

      # Find a session by ID, ensuring its db file lives under this PUN user's
      # dataroot.  On shared NFS, Session.all can read files owned by other
      # users; this ownership check prevents cross-user information disclosure.
      def find_owned_session(session_id)
        expected_db_root = ::BatchConnect::Session.db_root.to_s
        ::BatchConnect::Session.all.find do |s|
          s.id == session_id && s.db_file&.to_s&.start_with?(expected_db_root)
        end
      end

      # Get human-readable session status
      def session_status(session)
        return 'completed' if session.completed?
        return 'running' if session.running?
        return 'queued' if session.queued?

        'unknown'
      rescue StandardError
        'unknown'
      end

      # Build connection URL from connection info
      def build_connection_url(connection_info)
        host = connection_info[:host] || connection_info['host']
        port = connection_info[:port] || connection_info['port']
        password = connection_info[:password] || connection_info['password']

        return nil unless host && port

        # For HTTP-based apps (Jupyter, RStudio), build proxy URL
        "/node/#{host}/#{port}/"
      rescue StandardError => e
        Rails.logger.warn("Internal API: Error building connection URL: #{e.message}")
        nil
      end
    end
  end
end
