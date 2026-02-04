# frozen_string_literal: true

# Admin API Controller for batch connect session management
# This provides admin/service-level access to manage sessions for all users
#
# Supports user impersonation via Apache-mediated PUN forwarding:
# When target_user differs from the current PUN user, requests are forwarded
# back through Apache to the target user's PUN. Apache handles:
# - Starting the target user's PUN if not running (via pun_proxy.lua)
# - Authenticating the internal impersonation request (via api_auth.lua)
# - Routing to the target user's PUN
#
# This approach uses Apache's existing sudo permissions (www-data) instead of
# requiring all users to have sudo access.

require 'etc'
require 'net/http'
require 'uri'
require 'json'
require 'ostruct'
require_relative '../../../../services/volume_webhook_service'
require_relative '../../../../services/pun_manager'

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
            session = session_info[:session]
            user_context = session.user_context rescue {}
            # Use target_user if set (admin-created sessions), otherwise use directory owner
            effective_user = user_context['target_user'] || session_info[:user]
            {
              id: session.id,
              user: effective_user,
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

        rescue PunManager::UserNotFoundError => e
          render json: {
            status: 'error',
            code: 'USER_NOT_FOUND',
            message: e.message
          }, status: :not_found

        rescue ImpersonationError => e
          render json: {
            status: 'error',
            code: e.code,
            message: e.message
          }, status: e.http_status

        rescue Net::OpenTimeout, Net::ReadTimeout => e
          render json: {
            status: 'error',
            code: 'IMPERSONATION_TIMEOUT',
            message: "Timeout during impersonation request: #{e.message}"
          }, status: :gateway_timeout

        rescue Errno::ECONNREFUSED => e
          render json: {
            status: 'error',
            code: 'IMPERSONATION_CONNECTION_FAILED',
            message: "Could not connect to Apache for impersonation: #{e.message}"
          }, status: :bad_gateway

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
                      label: (attr.respond_to?(:label) ? attr.label : attr.id.to_s),
                      widget: (attr.respond_to?(:widget) ? attr.widget : 'text_field'),
                      required: (attr.respond_to?(:required?) ? attr.required? : (attr.opts[:required] rescue false)),
                      value: (attr.respond_to?(:value) ? attr.value : nil),
                      help: (attr.respond_to?(:help) ? attr.help : nil)
                    }
                    
                    # Add widget-specific fields
                    widget = attribute_hash[:widget]
                    case widget
                    when 'select', 'radio_button'
                      attribute_hash[:options] = attr.opts[:options] if attr.opts[:options]
                    when 'number_field'
                      attribute_hash[:min] = attr.opts[:min] if attr.opts[:min]
                      attribute_hash[:max] = attr.opts[:max] if attr.opts[:max]
                      attribute_hash[:step] = attr.opts[:step] if attr.opts[:step]
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
              label: (attr.respond_to?(:label) ? attr.label : attr.id.to_s),
              widget: (attr.respond_to?(:widget) ? attr.widget : 'text_field'),
              required: (attr.respond_to?(:required?) ? attr.required? : (attr.opts[:required] rescue false)),
              value: (attr.respond_to?(:value) ? attr.value : nil),
              help: (attr.respond_to?(:help) ? attr.help : nil)
            }
            
            # Add widget-specific fields
            widget = attribute_hash[:widget]
            case widget
            when 'select', 'radio_button'
              attribute_hash[:options] = attr.opts[:options] if attr.opts[:options]
            when 'number_field'
              attribute_hash[:min] = attr.opts[:min] if attr.opts[:min]
              attribute_hash[:max] = attr.opts[:max] if attr.opts[:max]
              attribute_hash[:step] = attr.opts[:step] if attr.opts[:step]
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
        # 
        # Uses impersonation to read sessions from the target user's PUN context,
        # ensuring proper file permissions are respected.
        def list_user_sessions(username)
          # Use impersonation if enabled and target user differs from current PUN user
          if should_impersonate_for_list?(username)
            return list_sessions_via_impersonation(username)
          end

          # Fallback: direct file read (only works if current user can read target's files)
          sessions = []

          user_dataroot = get_user_dataroot(username)
          batch_connect_dir = user_dataroot.join('batch_connect')
          if batch_connect_dir.exist?
            sessions.concat(load_user_sessions_from_dataroot(batch_connect_dir, username))
          end

          sessions
        end

        # Check if we should use impersonation for listing sessions
        def should_impersonate_for_list?(target_user)
          return false unless PunManager.impersonation_enabled?

          current_pun_user = get_current_pun_user
          target_user != current_pun_user
        end

        # List sessions via Apache-mediated impersonation
        def list_sessions_via_impersonation(username)
          Rails.logger.info("Admin API: Listing sessions for #{username} via impersonation")

          # Validate user exists
          PunManager.validate_user(username)

          # Forward request through Apache to target user's PUN
          response = forward_list_request_via_apache(username)

          # Parse response
          handle_list_impersonation_response(response, username)

        rescue PunManager::UserNotFoundError => e
          Rails.logger.error("Admin API: Impersonation failed for list - #{e.message}")
          []
        rescue StandardError => e
          Rails.logger.error("Admin API: Error listing sessions via impersonation: #{e.message}")
          []
        end

        # Forward list request through Apache to target user's PUN
        def forward_list_request_via_apache(target_user)
          uri = URI('http://127.0.0.1/pun/sys/dashboard/internal/batch_connect/sessions')

          http = Net::HTTP.new(uri.host, uri.port)
          http.open_timeout = 10
          http.read_timeout = 30

          request = Net::HTTP::Get.new(uri.path)
          request['Accept'] = 'application/json'

          # Set Host header to match Apache's ServerName
          begin
            original_host = self.request.host_with_port
          rescue
            original_host = ENV['OOD_SERVER_NAME'] || 'localhost'
          end
          request['Host'] = original_host

          # Impersonation headers
          request['X-Impersonate-User'] = target_user
          request['X-Internal-Token'] = PunManager.internal_api_token

          Rails.logger.debug("Admin API: Forwarding list request to Apache for user #{target_user}")
          http.request(request)
        end

        # Handle response from list impersonation request
        def handle_list_impersonation_response(response, username)
          unless response.is_a?(Net::HTTPSuccess)
            Rails.logger.error("Admin API: List impersonation failed: #{response.code} #{response.message}")
            return []
          end

          data = parse_json_response(response.body)
          unless data && data['status'] == 'success'
            Rails.logger.error("Admin API: List impersonation response missing success status")
            return []
          end

          # Convert response data to session_info format expected by caller
          (data['sessions'] || []).map do |session_data|
            # Create a mock session object that responds to the methods we need
            session = OpenStruct.new(
              id: session_data['id'],
              job_id: session_data['job_id'],
              title: session_data['title'],
              created_at: session_data['created_at'],
              cluster_id: session_data['cluster_id'],
              token: session_data['token']
            )

            # Add user_context method that returns project info
            session.define_singleton_method(:user_context) do
              { 'project' => session_data['project'] }
            end

            # Add status-related methods
            status = session_data['status']
            session.define_singleton_method(:completed?) { status == 'completed' }
            session.define_singleton_method(:running?) { status == 'running' }
            session.define_singleton_method(:queued?) { status == 'queued' }

            { user: username, session: session }
          end
        end

        # Get target_user from session context (for admin-created sessions)
        def session_target_user(session)
          context = session.user_context rescue {}
          context['target_user']
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
        # 
        # If impersonation is enabled and target_user differs from the current PUN user,
        # the request is forwarded to the target user's PUN to create the session in
        # the correct context. This ensures pods run in the target user's namespace.
        #
        # If impersonation is disabled or not needed, falls back to the legacy behavior
        # of creating in admin's dataroot with target_user metadata.
        def create_session_for_user(username, app, context)
          current_pun_user = get_current_pun_user

          # Check if we should use impersonation
          if should_impersonate?(username, current_pun_user)
            Rails.logger.info("Admin API: Using impersonation to create session for #{username} (current PUN: #{current_pun_user})")
            return create_session_via_impersonation(username, app.token, context)
          end

          # Fall back to legacy behavior (same user or impersonation disabled)
          Rails.logger.info("Admin API: Creating session locally for #{username}")
          create_session_locally(username, app, context)
        rescue StandardError => e
          Rails.logger.error("Admin API: Error creating session for user #{username}: #{e.message}")
          Rails.logger.error("Admin API: Backtrace: #{e.backtrace.join("\n")}")
          nil
        end

        # Get the current PUN user (the user whose PUN is handling this request)
        def get_current_pun_user
          OodSupport::User.new.name
        rescue StandardError
          ENV['USER'] || 'unknown'
        end

        # Determine if we should use impersonation for this request
        def should_impersonate?(target_user, current_pun_user)
          # Impersonation must be enabled
          return false unless PunManager.impersonation_enabled?

          # Internal API token must be configured
          return false if PunManager.internal_api_token.blank?

          # Only impersonate if target differs from current
          target_user != current_pun_user
        end

        # Create session via Apache-mediated PUN forwarding (impersonation)
        #
        # This method:
        # 1. Makes an HTTP request back through Apache with impersonation headers
        # 2. Apache's api_auth.lua validates the internal token and sets REMOTE_USER
        # 3. Apache's pun_proxy.lua starts the target user's PUN if needed
        # 4. Request is forwarded to the target user's PUN
        # 5. Session is created in the target user's context
        #
        # Benefits over direct Unix socket approach:
        # - Uses Apache's existing sudo permissions (www-data)
        # - Leverages pun_proxy.lua's battle-tested PUN startup logic
        # - No need for user-level sudo permissions
        def create_session_via_impersonation(username, app_token, context)
          # Log the impersonation attempt
          log_impersonation_attempt('create_session', username)

          # Validate user exists before attempting impersonation
          PunManager.validate_user(username)

          # Build request payload for internal API
          payload = {
            app_token: app_token,
            context: context.respond_to?(:to_h) ? context.to_h : context.attributes
          }

          # Add volume integration parameters if present
          if context.respond_to?(:attributes)
            attrs = context.attributes
            payload[:storage_path] = attrs['storage_path'] if attrs['storage_path'].present?
            payload[:volume_session_id] = attrs['volume_session_id'] if attrs['volume_session_id'].present?
          end

          # Forward request through Apache to target user's PUN
          response = forward_create_request_via_apache(username, payload)

          # Parse response and create session object
          handle_impersonation_response(response, username)

        rescue PunManager::UserNotFoundError => e
          Rails.logger.error("Admin API: Impersonation failed - #{e.message}")
          log_impersonation_failure('create_session', username, 'USER_NOT_FOUND', e.message)
          raise ImpersonationError.new('USER_NOT_FOUND', e.message, :not_found)
        end

        # Forward session creation request through Apache to target user's PUN
        #
        # Apache handles:
        # - Validating the internal token (api_auth.lua)
        # - Setting REMOTE_USER to target user (api_auth.lua)
        # - Starting target user's PUN if not running (pun_proxy.lua)
        # - Routing request to target user's PUN (pun_proxy.lua)
        def forward_create_request_via_apache(target_user, payload)
          # Use localhost to reach Apache
          # Apache listens on port 80 inside the container
          uri = URI('http://127.0.0.1/pun/sys/dashboard/internal/batch_connect/sessions')

          http = Net::HTTP.new(uri.host, uri.port)
          http.open_timeout = 10  # Seconds to wait for connection
          http.read_timeout = 60  # Seconds to wait for response (PUN startup can take time)

          request = Net::HTTP::Post.new(uri.path)
          request['Content-Type'] = 'application/json'
          request['Accept'] = 'application/json'

          # Set Host header to match Apache's ServerName to prevent 301 redirects
          # Use the host from the incoming request so Apache recognizes it
          begin
            original_host = self.request.host_with_port
          rescue
            original_host = ENV['OOD_SERVER_NAME'] || 'localhost'
          end
          request['Host'] = original_host

          # Impersonation headers - api_auth.lua validates these
          request['X-Impersonate-User'] = target_user
          request['X-Internal-Token'] = PunManager.internal_api_token

          request.body = payload.to_json

          Rails.logger.debug("Admin API: Forwarding impersonation request to Apache for user #{target_user}")
          response = http.request(request)
          Rails.logger.debug("Admin API: Apache response: #{response.code} #{response.message}")

          response
        end

        # Handle response from impersonation request (Net::HTTP response)
        def handle_impersonation_response(response, username)
          # Check HTTP status
          unless response.is_a?(Net::HTTPSuccess)
            error_data = parse_json_response(response.body)
            error_msg = error_data['message'] || "Internal API returned #{response.code}"
            error_code = error_data['code'] || 'IMPERSONATION_FAILED'

            Rails.logger.error("Admin API: Impersonation request failed: #{error_msg}")
            log_impersonation_failure('create_session', username, error_code, error_msg)

            # Map HTTP status to appropriate error
            http_status = case response.code.to_i
                          when 401 then :unauthorized
                          when 404 then :not_found
                          when 503 then :service_unavailable
                          when 504 then :gateway_timeout
                          else :bad_gateway
                          end

            raise ImpersonationError.new(error_code, error_msg, http_status)
          end

          data = parse_json_response(response.body)
          unless data && data['status'] == 'success'
            error_msg = data&.dig('message') || 'Impersonation response missing success status'
            Rails.logger.error("Admin API: #{error_msg}")
            log_impersonation_failure('create_session', username, 'INVALID_RESPONSE', error_msg)
            raise ImpersonationError.new('INVALID_RESPONSE', error_msg, :bad_gateway)
          end

          # Log successful impersonation
          log_impersonation_success('create_session', username, data['id'])

          # Return a session-like object with the response data
          ImpersonatedSession.new(data)
        end

        # Parse JSON response body safely
        def parse_json_response(body)
          return {} if body.nil? || body.empty?
          JSON.parse(body)
        rescue JSON::ParserError => e
          Rails.logger.warn("Admin API: Failed to parse JSON response: #{e.message}")
          {}
        end

        # Log impersonation attempt for audit
        def log_impersonation_attempt(action, target_user)
          Rails.logger.info({
            event: 'admin_api_impersonation_attempt',
            action: action,
            admin_user: get_current_pun_user,
            target_user: target_user,
            timestamp: Time.now.utc.iso8601,
            remote_ip: request.remote_ip
          }.to_json)
        end

        # Log successful impersonation for audit
        def log_impersonation_success(action, target_user, session_id)
          Rails.logger.info({
            event: 'admin_api_impersonation_success',
            action: action,
            admin_user: get_current_pun_user,
            target_user: target_user,
            session_id: session_id,
            timestamp: Time.now.utc.iso8601,
            remote_ip: request.remote_ip
          }.to_json)
        end

        # Log failed impersonation for audit
        def log_impersonation_failure(action, target_user, error_code, error_message)
          Rails.logger.warn({
            event: 'admin_api_impersonation_failure',
            action: action,
            admin_user: get_current_pun_user,
            target_user: target_user,
            error_code: error_code,
            error_message: error_message,
            timestamp: Time.now.utc.iso8601,
            remote_ip: request.remote_ip
          }.to_json)
        end

        # Legacy session creation - creates in admin's dataroot with target_user metadata
        def create_session_locally(username, app, context)
          session = ::BatchConnect::Session.new
          save_result = session.save(app: app, context: context)
          
          unless save_result
            Rails.logger.error("Admin API: Session save failed for user #{username}")
            return nil
          end

          # Store target_user in the user_defined_context file
          store_target_user_metadata(session, username)

          Rails.logger.info("Admin API: Created session #{session.id} for target user #{username}")
          session
        end

        # Error class for impersonation failures
        class ImpersonationError < StandardError
          attr_reader :code, :http_status

          def initialize(code, message, http_status = :bad_gateway)
            @code = code
            @http_status = http_status
            super(message)
          end
        end

        # Wrapper class for session data returned from impersonation
        class ImpersonatedSession
          attr_reader :id, :job_id, :created_at, :user, :session_url

          def initialize(data)
            @id = data['id'] || data['session_id']
            @job_id = data['job_id']
            @created_at = data['created_at']
            @user = data['user']
            @session_url = data['session_url']
          end

          # Compatibility with BatchConnect::Session interface
          def session_id
            @id
          end
        end

        # Store target_user in session's user context file
        def store_target_user_metadata(session, target_user)
          begin
            context_file = session.staged_root.join("user_defined_context.json")
            if context_file.exist?
              context_data = JSON.parse(context_file.read)
            else
              context_data = {}
            end
            
            context_data['target_user'] = target_user
            context_file.write(JSON.pretty_generate(context_data))
            Rails.logger.debug("Admin API: Stored target_user=#{target_user} in session #{session.id}")
          rescue StandardError => e
            Rails.logger.warn("Admin API: Could not store target_user metadata: #{e.message}")
          end
        end

        # Move session files from admin's dataroot to target user's dataroot
        # This ensures the session appears in the correct user's session list
        def move_session_to_user(session, username)
          admin_db_file = session.db_file
          admin_staged_root = session.staged_root

          # Calculate target user's paths
          user_dataroot = get_user_dataroot(username)
          user_batch_connect_dir = user_dataroot.join('batch_connect')
          
          # Determine cluster for per-cluster dataroot (if enabled)
          # Use the session's staged_root to determine the correct cluster path format
          # This handles the per_cluster_dataroot configuration automatically
          cluster_path = ''
          begin
            # Check if per_cluster_dataroot is enabled by comparing staged_root pattern
            if ::Configuration.respond_to?(:per_cluster_dataroot?) && ::Configuration.per_cluster_dataroot?
              cluster_path = session.cluster_id.to_s
            end
          rescue => e
            Rails.logger.debug("Admin API: Could not determine per_cluster_dataroot setting: #{e.message}")
          end
          
          user_session_dataroot = user_batch_connect_dir.join(cluster_path).join(session.token.to_s)
          user_db_root = user_session_dataroot.join('db')
          user_output_root = user_session_dataroot.join('output')

          Rails.logger.info("Admin API: Moving session #{session.id} from admin to user #{username}")
          Rails.logger.debug("Admin API: Source db_file: #{admin_db_file}")
          Rails.logger.debug("Admin API: Source staged_root: #{admin_staged_root}")
          Rails.logger.debug("Admin API: Target db_root: #{user_db_root}")
          Rails.logger.debug("Admin API: Target output_root: #{user_output_root}")

          # Create target directories with proper permissions using sudo
          # The PUN runs as the admin user, so we need elevated privileges to create dirs in other users' homes
          create_user_directory(user_db_root, username)
          create_user_directory(user_output_root, username)

          # Move the database file (session metadata) using sudo
          target_db_file = user_db_root.join(session.id)
          if admin_db_file.exist?
            result = system("sudo mv '#{admin_db_file}' '#{target_db_file}'")
            if result
              Rails.logger.debug("Admin API: Moved db file to #{target_db_file}")
            else
              Rails.logger.error("Admin API: Failed to move db file to #{target_db_file}")
              return false
            end
          else
            Rails.logger.warn("Admin API: Source db_file does not exist: #{admin_db_file}")
          end

          # Move the staged output directory (job scripts, connection info, etc.) using sudo
          target_staged_root = user_output_root.join(session.id)
          if admin_staged_root.exist?
            result = system("sudo mv '#{admin_staged_root}' '#{target_staged_root}'")
            if result
              Rails.logger.debug("Admin API: Moved staged_root to #{target_staged_root}")
            else
              Rails.logger.error("Admin API: Failed to move staged_root to #{target_staged_root}")
              return false
            end
          else
            Rails.logger.warn("Admin API: Source staged_root does not exist: #{admin_staged_root}")
          end

          # Set ownership to target user
          set_user_ownership(target_db_file, username)
          set_user_ownership(target_staged_root, username)

          Rails.logger.info("Admin API: Successfully moved session #{session.id} to user #{username}")
          true
        rescue StandardError => e
          Rails.logger.error("Admin API: Error moving session to user #{username}: #{e.message}")
          Rails.logger.error("Admin API: Backtrace: #{e.backtrace.join("\n")}")
          false
        end

        # Create directory with sudo and set ownership to specified user
        # Returns true if successful, false otherwise
        def create_user_directory(path, username)
          return true if path.exist?

          begin
            # Use sudo to create directory and set ownership
            cmd = "sudo mkdir -p '#{path}' && sudo chmod 700 '#{path}'"
            result = system(cmd)
            
            unless result
              Rails.logger.error("Admin API: Failed to create directory #{path}")
              return false
            end

            # Set ownership using sudo chown
            set_user_ownership(path, username)
            true
          rescue StandardError => e
            Rails.logger.error("Admin API: Error creating directory #{path}: #{e.message}")
            false
          end
        end

        # Set ownership of path to specified user using sudo
        # This is needed so the user can access their session files
        def set_user_ownership(path, username)
          return unless path.exist?

          begin
            # Get user's uid/gid from passwd
            user_info = Etc.getpwnam(username)
            
            # Use sudo to change ownership since we may not have permission
            cmd = "sudo chown -R #{user_info.uid}:#{user_info.gid} '#{path}'"
            result = system(cmd)
            
            if result
              Rails.logger.debug("Admin API: Set ownership of #{path} to #{username} (#{user_info.uid}:#{user_info.gid})")
            else
              Rails.logger.warn("Admin API: sudo chown failed for #{path}")
            end
          rescue ArgumentError => e
            # User not found in passwd - this is expected if running without proper user database
            Rails.logger.warn("Admin API: Could not set ownership for #{username}: #{e.message}")
          rescue StandardError => e
            Rails.logger.warn("Admin API: Error setting ownership: #{e.message}")
          end
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
