# frozen_string_literal: true

# Admin API Controller for batch connect session management
# This provides admin/service-level access to manage sessions for all users

require_relative '../../../../services/volume_webhook_service'

module Api
  module V1
    module BatchConnect
      class SessionsController < ApplicationController
        # Skip CSRF verification for API calls
        skip_before_action :verify_authenticity_token

        # Authenticate admin API requests
        before_action :authenticate_admin_api_request

        # Storage path validation pattern: alphanumeric, hyphens, underscores, forward slashes only
        STORAGE_PATH_PATTERN = /\A[a-zA-Z0-9\/_-]+\z/.freeze
        STORAGE_PATH_MAX_LENGTH = 255

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
        # Optional body parameters (Volume Integration v1.1):
        #   - storage_path: relative NFS path for volume mount
        #   - volume_session_id: Volume API session ID for webhook linkage
        #
        # Returns:
        # {
        #   "status": "success",
        #   "id": "uuid",
        #   "session_id": "uuid",
        #   "user": "username",
        #   "job_id": "...",
        #   "volume_session_id": "..." (if provided)
        #   ...
        # }
        def create
          target_user = params.require(:target_user)
          app_token = params.require(:app_token)
          context_params = params.require(:context).permit!.to_hash

          # Extract optional volume integration parameters
          storage_path = params[:storage_path]
          volume_session_id = params[:volume_session_id]

          Rails.logger.info("Admin API: Creating session for user #{target_user}")

          # Validate storage_path if provided
          if storage_path.present?
            validation_error = validate_storage_path(storage_path)
            if validation_error
              return render json: {
                status: 'error',
                message: validation_error
              }, status: :bad_request
            end
          end

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

          # Pass volume integration parameters to context for template use
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
              message: 'Invalid context parameters',
              errors: context.errors.full_messages
            }, status: :unprocessable_entity
          end

          # Create session for user with volume metadata
          session = create_session_for_user(target_user, app, context)

          if session
            # Store volume metadata in session info for later retrieval
            store_volume_metadata(session, storage_path, volume_session_id)

            Rails.logger.info("Admin API: Created session #{session.id} for user #{target_user}")

            response_data = {
              status: 'success',
              id: session.id,
              session_id: session.id,
              user: target_user,
              job_id: session.job_id,
              created_at: session.created_at,
              session_url: "/batch_connect/sessions/#{session.id}"
            }

            # Include volume_session_id in response if provided
            response_data[:volume_session_id] = volume_session_id if volume_session_id.present?

            render json: response_data, status: :created
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

          # Get connection URL if session is running
          connection_url = nil
          if session.running?
            begin
              connection_info = session.connect.to_h
              connection_url = build_connection_url(connection_info)
            rescue StandardError => e
              Rails.logger.warn("Admin API: Could not get connection URL for session #{session.id}: #{e.message}")
            end
          end

          # Build session response with volume integration fields
          session_data = {
            id: session.id,
            user: user,
            job_id: session.job_id,
            created_at: session.created_at,
            title: session.title,
            cluster_id: session.cluster_id,
            token: session.token,
            info: session.info.to_h,
            status: session_status(session),
            connect_url: connection_url
          }

          # Include volume_session_id if present (FR-2)
          vol_session_id = session_volume_id(session)
          session_data[:volume_session_id] = vol_session_id if vol_session_id.present?

          render json: {
            status: 'success',
            session: session_data
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

          # Build connection URL based on connection type
          connection_url = build_connection_url(connection_info)

          Rails.logger.info("Admin API: Retrieved connection info for session #{session.id} (user: #{user})")

          render json: {
            status: 'success',
            user: user,
            session_status: session_state,
            connection: connection_info,
            connection_url: connection_url
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
        # Sends webhook to Volume API if volume_session_id was set (FR-3)
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
            # Send webhook before destroying session (FR-3)
            # This is fire-and-forget - failures don't affect session cleanup
            send_session_ended_webhook(session, 'cancelled', 'User terminated session via API')

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
        # GET /api/v1/batch_connect/sessions/apps
        # List available batch connect apps
        # 
        # Query parameters:
        #   - details: (optional) if true, include form attributes for all apps
        # 
        # Returns basic app info by default, or detailed info with form attributes if details=true
        def apps
          include_details = params[:details] == 'true'
          
          apps = SysRouter.apps.select { |app| app.type == :sys && app.name.start_with?("bc_") }.map do |app|
            app_data = {
              token: app.token,
              title: app.title,
              description: (app.manifest.description rescue ""),
              icon_uri: (app.icon_uri rescue "")
            }
            
            if include_details
              begin
                bc_app = ::BatchConnect::App.from_token(app.token)
                if bc_app && bc_app.valid?
                  attributes_data = bc_app.attributes.map do |attr|
                    attribute_hash = {
                      id: attr.id.to_s,
                      label: attr.label,
                      widget: attr.widget,
                      required: attr.required?,
                      value: attr.value,
                      help: attr.help
                    }
                    
                    # Add widget-specific fields
                    case attr.widget
                    when 'select', 'radio_button'
                      attribute_hash[:options] = attr.options if attr.respond_to?(:options)
                    when 'number_field'
                      attribute_hash[:min] = attr.min if attr.respond_to?(:min)
                      attribute_hash[:max] = attr.max if attr.respond_to?(:max)
                      attribute_hash[:step] = attr.step if attr.respond_to?(:step)
                    end
                    
                    attribute_hash
                  end
                  app_data[:attributes] = attributes_data
                end
              rescue => e
                Rails.logger.warn("Admin API: Could not get attributes for #{app.token}: #{e.message}")
              end
            end
            
            app_data
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

        # GET /api/v1/batch_connect/sessions/app_details?token=sys/bc_jupyter
        # Get detailed information about a specific app including form attributes
        #
        # Query parameters:
        #   - token: app token (e.g., "sys/bc_jupyter")
        #
        # Returns:
        # {
        #   "status": "success",
        #   "app": {
        #     "token": "sys/bc_jupyter",
        #     "title": "Jupyter (Kubernetes)",
        #     "description": "...",
        #     "icon_uri": "...",
        #     "attributes": [
        #       {
        #         "id": "project",
        #         "label": "Project",
        #         "widget": "text_field",
        #         "required": true,
        #         "value": null,
        #         "options": null
        #       },
        #       ...
        #     ]
        #   }
        # }
        def app_details
          token = params.require(:token)
          
          Rails.logger.info("Admin API: Getting details for app #{token}")
          
          app = ::BatchConnect::App.from_token(token)
          unless app && app.valid?
            return render json: {
              status: 'error',
              message: "Batch connect app not found: #{token}"
            }, status: :not_found
          end

          # Build attributes with metadata
          attributes_data = app.attributes.map do |attr|
            attribute_hash = {
              id: attr.id.to_s,
              label: attr.label,
              widget: attr.widget,
              required: attr.required?,
              value: attr.value,
              help: attr.help
            }
            
            # Add widget-specific fields
            case attr.widget
            when 'select', 'radio_button'
              attribute_hash[:options] = attr.options if attr.respond_to?(:options)
            when 'number_field'
              attribute_hash[:min] = attr.min if attr.respond_to?(:min)
              attribute_hash[:max] = attr.max if attr.respond_to?(:max)
              attribute_hash[:step] = attr.step if attr.respond_to?(:step)
            end
            
            attribute_hash
          end

          render json: {
            status: 'success',
            app: {
              token: app.token,
              title: app.title,
              description: app.description,
              icon_uri: app.icon_uri,
              attributes: attributes_data
            }
          }
        rescue ActionController::ParameterMissing => e
          render json: {
            status: 'error',
            message: "Missing required parameter: #{e.param}"
          }, status: :bad_request
        rescue StandardError => e
          Rails.logger.error("Admin API: Error getting app details: #{e.class} - #{e.message}")
          Rails.logger.error("Admin API: Backtrace: #{e.backtrace.join("\n")}")
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

        # Build connection URL from connection info
        # Supports multiple connection types (node, websocket, etc.)
        def build_connection_url(connection_info)
          # Handle both symbol and string keys
          host = connection_info[:host] || connection_info['host']
          port = connection_info[:port] || connection_info['port']
          websocket = connection_info[:websocket] || connection_info['websocket']
          
          # For Kubernetes-based sessions (Jupyter, RStudio), use /node/host/port format
          if host && port
            "/node/#{host}/#{port}/"
          # For VNC sessions, use websocket format
          elsif websocket && host
            "/rnode/#{host}/#{websocket}/websockify"
          # Fallback: return nil if we can't determine URL
          else
            nil
          end
        end

        # Validate storage path for security
        # Returns error message if invalid, nil if valid
        #
        # @param storage_path [String] The storage path to validate
        # @return [String, nil] Error message or nil if valid
        def validate_storage_path(storage_path)
          # Check max length
          if storage_path.length > STORAGE_PATH_MAX_LENGTH
            return "Invalid storage_path: must be #{STORAGE_PATH_MAX_LENGTH} characters or less"
          end

          # Check for absolute paths (must be relative)
          if storage_path.start_with?('/')
            return 'Invalid storage_path: must be relative (no leading slash)'
          end

          # Check for directory traversal attempts
          if storage_path.include?('..')
            return 'Invalid storage_path: cannot contain parent directory references (..)'
          end

          # Check pattern (alphanumeric, hyphens, underscores, forward slashes only)
          unless storage_path.match?(STORAGE_PATH_PATTERN)
            return 'Invalid storage_path: must contain only alphanumeric characters, hyphens, underscores, and forward slashes'
          end

          nil # Valid
        end

        # Store volume metadata in session info
        #
        # @param session [BatchConnect::Session] The session to update
        # @param storage_path [String, nil] The storage path
        # @param volume_session_id [String, nil] The volume session ID
        def store_volume_metadata(session, storage_path, volume_session_id)
          return unless storage_path.present? || volume_session_id.present?

          begin
            # Get existing info hash
            info = session.info.to_h rescue {}
            
            # Add volume metadata
            info[:storage_path] = storage_path if storage_path.present?
            info[:volume_session_id] = volume_session_id if volume_session_id.present?
            
            # Update session info
            # Note: OOD Session stores info in the session file
            if session.respond_to?(:info=)
              session.info = info
            end

            Rails.logger.debug("Admin API: Stored volume metadata for session #{session.id}: " \
                              "storage_path=#{storage_path}, volume_session_id=#{volume_session_id}")
          rescue StandardError => e
            Rails.logger.warn("Admin API: Could not store volume metadata for session #{session.id}: #{e.message}")
          end
        end

        # Get volume_session_id from session info
        #
        # @param session [BatchConnect::Session] The session
        # @return [String, nil] The volume session ID if present
        def session_volume_id(session)
          info = session.info.to_h rescue {}
          info[:volume_session_id] || info['volume_session_id']
        end

        # Send session-ended webhook to Volume API (FR-3)
        # This is fire-and-forget - failures are logged but don't affect session cleanup
        #
        # @param session [BatchConnect::Session] The session that ended
        # @param exit_status [String] The exit status (completed, failed, timeout, cancelled, unknown)
        # @param exit_reason [String] Human-readable reason for termination
        def send_session_ended_webhook(session, exit_status, exit_reason)
          # Determine exit status from session if not explicitly provided
          exit_status = VolumeWebhookService.determine_exit_status(session) if exit_status.nil?

          # Send the webhook asynchronously
          VolumeWebhookService.send_session_ended(
            session,
            exit_status,
            exit_reason: exit_reason
          )
        rescue StandardError => e
          # Log error but don't fail - webhook is fire-and-forget
          Rails.logger.error("Admin API: Error sending webhook for session #{session.id}: #{e.message}")
        end
      end
    end
  end
end
