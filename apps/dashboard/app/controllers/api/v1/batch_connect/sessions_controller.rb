# frozen_string_literal: true

# Admin API Controller for batch connect session management
# This provides admin/service-level access to manage sessions for all users

module Api
  module V1
    module BatchConnect
      class SessionsController < ApplicationController
        # Skip CSRF verification for API calls
        skip_before_action :verify_authenticity_token

        # Authenticate admin API requests
        before_action :authenticate_admin_api_request

        # GET /api/v1/batch_connect/sessions
        # List all batch connect sessions (optionally filtered by user)
        #
        # Query parameters:
        #   - user: (optional) filter sessions by username
        #
        # Returns:
        # {
        #   "status": "success",
        #   "sessions": [...]
        # }
        def index
          target_user = params[:user]

          if target_user
            Rails.logger.info("Admin API: Listing sessions for user #{target_user}")
            sessions = list_user_sessions(target_user)
          else
            Rails.logger.info("Admin API: Listing all sessions")
            sessions = list_all_sessions
          end

          sessions_data = sessions.map do |session_info|
            {
              id: session_info[:session].id,
              user: session_info[:user],
              job_id: session_info[:session].job_id,
              title: session_info[:session].title,
              status: session_status(session_info[:session]),
              created_at: session_info[:session].created_at,
              cluster_id: session_info[:session].cluster_id,
              token: session_info[:session].token
            }
          end

          render json: {
            status: 'success',
            sessions: sessions_data
          }
        rescue StandardError => e
          Rails.logger.error("Admin API: Error listing sessions: #{e.class} - #{e.message}")
          render json: {
            status: 'error',
            message: e.message
          }, status: :internal_server_error
        end

        # POST /api/v1/batch_connect/sessions
        # Create a new session for a specified user
        #
        # Required body parameters:
        #   - target_user: username to create session for
        #   - app_token: batch connect app (e.g., "sys/bc_jupyter")
        #   - context: form parameters for the app
        #
        # Returns:
        # {
        #   "status": "success",
        #   "session_id": "uuid",
        #   "user": "username",
        #   "job_id": "...",
        #   ...
        # }
        def create
          target_user = params.require(:target_user)
          app_token = params.require(:app_token)
          context_params = params.require(:context).permit!.to_hash

          Rails.logger.info("Admin API: Creating session for user #{target_user}")

          # Load the app
          app = ::BatchConnect::App.from_token(app_token)
          unless app && app.valid?
            return render json: {
              status: 'error',
              message: "Batch connect app not found: #{app_token}"
            }, status: :not_found
          end

          # Create context and session using app's build_session_context
          # This properly sets up attribute accessors for the app's form fields
          context = app.build_session_context
          context.attributes = context_params

          unless context.valid?
            return render json: {
              status: 'error',
              message: 'Invalid context parameters',
              errors: context.errors.full_messages
            }, status: :unprocessable_entity
          end

          # Create session for user
          session = create_session_for_user(target_user, app, context)

          if session
            Rails.logger.info("Admin API: Created session #{session.id} for user #{target_user}")

            render json: {
              status: 'success',
              session_id: session.id,
              user: target_user,
              job_id: session.job_id,
              created_at: session.created_at,
              session_url: "/batch_connect/sessions/#{session.id}"
            }, status: :created
          else
            render json: {
              status: 'error',
              message: 'Failed to create session'
            }, status: :unprocessable_entity
          end

        rescue ActionController::ParameterMissing => e
          render json: {
            status: 'error',
            message: "Missing required parameter: #{e.param}"
          }, status: :bad_request

        rescue StandardError => e
          Rails.logger.error("Admin API: Error creating session: #{e.class} - #{e.message}")
          Rails.logger.error("Admin API: Backtrace: #{e.backtrace.join("\n")}")

          render json: {
            status: 'error',
            message: e.message
          }, status: :internal_server_error
        end

        # GET /api/v1/batch_connect/sessions/:id
        # Get details about a specific session
        #
        # Returns session details including which user owns it
        def show
          session_info = find_session_by_id(params[:id])

          unless session_info
            return render json: {
              status: 'error',
              message: 'Session not found'
            }, status: :not_found
          end

          session = session_info[:session]
          user = session_info[:user]

          render json: {
            status: 'success',
            session: {
              id: session.id,
              user: user,
              job_id: session.job_id,
              created_at: session.created_at,
              title: session.title,
              cluster_id: session.cluster_id,
              token: session.token,
              info: session.info.to_h,
              status: session_status(session)
            }
          }

        rescue StandardError => e
          Rails.logger.error("Admin API: Error retrieving session: #{e.class} - #{e.message}")
          render json: {
            status: 'error',
            message: e.message
          }, status: :internal_server_error
        end

        # GET /api/v1/batch_connect/sessions/:id/connect
        # Get connection details for a running session
        def connect
          session_info = find_session_by_id(params[:id])

          unless session_info
            return render json: {
              status: 'error',
              message: 'Session not found'
            }, status: :not_found
          end

          session = session_info[:session]
          user = session_info[:user]
          session_state = session_status(session)

          unless session.running?
            return render json: {
              status: 'error',
              message: "Session is not running (current status: #{session_state})",
              session_status: session_state,
              user: user
            }, status: :unprocessable_entity
          end

          # Get connection information
          connection_info = session.connect.to_h

          Rails.logger.info("Admin API: Retrieved connection info for session #{session.id} (user: #{user})")

          render json: {
            status: 'success',
            user: user,
            session_status: session_state,
            connection: connection_info,
            connection_url: connection_info[:websocket] || connection_info['websocket']
          }
        rescue StandardError => e
          Rails.logger.error("Admin API: Error getting connection info: #{e.class} - #{e.message}")

          render json: {
            status: 'error',
            message: e.message
          }, status: :internal_server_error
        end

        # DELETE /api/v1/batch_connect/sessions/:id
        # Delete a session (for any user)
        def destroy
          session_info = find_session_by_id(params[:id])

          unless session_info
            return render json: {
              status: 'error',
              message: 'Session not found'
            }, status: :not_found
          end

          session = session_info[:session]
          user = session_info[:user]

          begin
            session.destroy
            Rails.logger.info("Admin API: Deleted session #{params[:id]} for user #{user}")

            render json: {
              status: 'success',
              message: 'Session deleted',
              user: user
            }
          rescue StandardError => e
            Rails.logger.error("Admin API: Error deleting session: #{e.class} - #{e.message}")
            render json: {
              status: 'error',
              message: e.message
            }, status: :internal_server_error
          end
        end

        # GET /api/v1/batch_connect/apps
        # List available batch connect apps
        def apps
          apps = SysRouter.apps.select { |app| app.type == :sys && app.name.start_with?("bc_") }.map do |app|
            {
              token: app.token,
              title: app.title,
              description: (app.manifest.description rescue ""),
              icon_uri: (app.icon_uri rescue "")
            }
          end

          render json: {
            status: 'success',
            apps: apps
          }
        rescue StandardError => e
          Rails.logger.error("Admin API: Error listing apps: #{e.class} - #{e.message}")
          render json: {
            status: 'error',
            message: e.message
          }, status: :internal_server_error
        end

        private

        # Authenticate admin API request
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

          Rails.logger.debug("Admin API: Authenticated with admin token")
          true
        end

        # Validate admin token
        # TODO: Implement proper token validation with database storage
        def validate_admin_token(token)
          # For now, accept tokens starting with 'ood-api-admin-'
          # In production: validate against stored admin tokens, check expiration, etc.
          token.start_with?('ood-api-admin-')
        end

        # List all sessions across all users
        # This requires accessing the base dataroot and iterating through user directories
        def list_all_sessions
          sessions = []
          base_dataroot = get_base_dataroot

          return sessions unless base_dataroot.exist?

          # Iterate through potential user directories
          base_dataroot.children.select(&:directory?).each do |user_dir|
            # Each user directory contains batch_connect data
            user_batch_connect_dir = user_dir.join('ondemand', 'data', 'sys', 'dashboard', 'batch_connect')
            next unless user_batch_connect_dir.exist?

            # Try to extract username from path or skip if not identifiable
            username = extract_username_from_path(user_dir)
            next unless username

            user_sessions = load_user_sessions_from_dataroot(user_batch_connect_dir, username)
            sessions.concat(user_sessions)
          end

          sessions
        end

        # List sessions for a specific user
        def list_user_sessions(username)
          user_dataroot = get_user_dataroot(username)
          batch_connect_dir = user_dataroot.join('batch_connect')

          return [] unless batch_connect_dir.exist?

          load_user_sessions_from_dataroot(batch_connect_dir, username)
        end

        # Load sessions from a user's batch_connect directory
        def load_user_sessions_from_dataroot(batch_connect_dir, username)
          sessions = []

          # Look for session files in the db directory
          # Structure: batch_connect/db/[session_id]
          batch_connect_dir.glob('db/*').select(&:file?).reject do |p|
            p.extname == ".bak"
          end.each do |session_file|
            begin
              session = ::BatchConnect::Session.new.from_json(session_file.read)
              # session.update_cache_completed! if session.respond_to?(:update_cache_completed!) # Commented out - causes nil.gsub errors
              sessions << { user: username, session: session } if session.valid_session_fields?
            rescue StandardError => e
              Rails.logger.warn("Admin API: Failed to load session from #{session_file}: #{e.message}")
            end
          end

          sessions
        end

        # Find session by ID across all users
        def find_session_by_id(session_id)
          base_dataroot = get_base_dataroot

          return nil unless base_dataroot.exist?

          # Search through all user directories
          base_dataroot.children.select(&:directory?).each do |user_dir|
            user_batch_connect_dir = user_dir.join('ondemand', 'data', 'sys', 'dashboard', 'batch_connect')
            next unless user_batch_connect_dir.exist?

            username = extract_username_from_path(user_dir)
            next unless username

            # Search for the session file
            session_file = user_batch_connect_dir.glob("db/#{session_id}").first

            if session_file&.file?
              begin
                session = ::BatchConnect::Session.new.from_json(session_file.read)
                # session.update_cache_completed! if session.respond_to?(:update_cache_completed!) # Commented out - causes nil.gsub errors
                return { user: username, session: session }
              rescue StandardError => e
                Rails.logger.error("Admin API: Error loading session #{session_id}: #{e.message}")
                return nil
              end
            end
          end

          nil
        end

        # Create session for a specific user
        def create_session_for_user(username, app, context)
          # Use the existing Session.save method but need to set up user context
          session = ::BatchConnect::Session.new
          session.save(app: app, context: context)
          session
        rescue StandardError => e
          Rails.logger.error("Admin API: Error creating session for user #{username}: #{e.message}")
          Rails.logger.error("Admin API: Backtrace: #{e.backtrace.join("\n")}")
          nil
        end

        # Get the base dataroot that contains all user directories
        def get_base_dataroot
          # In containerized OOD, user data is in /opt/ood-home
          dataroot_base = ENV['OOD_DATAROOT_BASE'] || '/opt/ood-home'
          Pathname.new(dataroot_base)
        end

        # Get a specific user's dataroot
        def get_user_dataroot(username)
          # In containerized OOD: /opt/ood-home/username/ondemand/data/sys/dashboard
          user_home = Pathname.new(ENV['OOD_USER_HOME_BASE'] || '/opt/ood-home').join(username)
          user_home.join('ondemand', 'data', 'sys', 'dashboard')
        end

        # Extract username from a user directory path
        def extract_username_from_path(user_dir)
          # Path is like /opt/ood-home/username/ondemand/data/sys/dashboard
          # Extract username (part after ood-home)
          parts = user_dir.to_s.split('/')
          # Find the index of 'ood-home' and get the next part
          ood_home_index = parts.index('ood-home')
          return nil unless ood_home_index
          
          parts[ood_home_index + 1]
        end

        # Determine session status
        def session_status(session)
          if session.completed?
            'completed'
          elsif session.running?
            'running'
          elsif session.queued?
            'queued'
          else
            'unknown'
          end
        end
      end
    end
  end
end
