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
require_relative '../../../../services/volume_api_client'
require_relative '../../../../services/pun_manager'
require_relative '../../../../services/impersonation_error'
require_relative '../../../../services/impersonated_session'
require_relative '../../../../services/impersonation_service'

module Api
  module V1
    module BatchConnect
      class SessionsController < ApplicationController
        include AdminApiAuthentication

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
        #   - live: (optional, default true) when listing all users, resolve
        #           job statuses by forwarding to each owner's PUN. Pass
        #           "false" to skip the fan-out and return cached statuses.
        #
        # Each session entry carries a status_source field:
        #   - "live":    evaluated in the owner's PUN (authoritative)
        #   - "cached":  from the session db's completed latch (authoritative,
        #                terminal)
        #   - "unknown": owner's PUN unreachable or fan-out skipped; the job
        #                state cannot be determined from this context
        #
        # Returns:
        # {
        #   "status": "success",
        #   "sessions": [...]
        # }
        def index
          target_user = params[:user]
          live = params[:live] != 'false'

          if target_user
            Rails.logger.info("Admin API: Listing sessions for user #{target_user}")
            sessions = list_user_sessions(target_user)
          else
            Rails.logger.info("Admin API: Listing all sessions (live: #{live})")
            sessions = list_all_sessions(live: live)
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
              # Entries that could not be evaluated in the owner's PUN carry an
              # explicit status; everything else is evaluated live here.
              status: session_info[:status] || session_status(session),
              status_source: session_info[:status_source] || 'live',
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

            # Validate the mount handle against the Volume API before launching, so a
            # stale / forged / wrong-owner / mismatched value cannot silently mount the
            # wrong storage (spec 049, FR-002/003/004). Only runs when a codespace
            # mount is requested (storage_path present); the no-codespace flow is
            # unaffected. Runs here, before create_session_for_user, so it covers both
            # the local and impersonation dispatch paths.
            volume_session_error = validate_volume_session(target_user, storage_path, volume_session_id)
            if volume_session_error
              return render json: {
                status: 'error',
                code: 'VOLUME_SESSION_INVALID',
                message: volume_session_error
              }, status: :unprocessable_entity
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

          # Ensure cluster is set when app has a single cluster (API clients often omit it)
          if context_params['cluster'].blank? && app.clusters.size == 1
            context_params = context_params.merge('cluster' => app.clusters.first.id.to_s)
          end
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

            # Mark the mount handle consumed now that the launch succeeded, so the
            # same volume_session_id cannot be reused (spec 049, US1#5). Done
            # server-side here -- covering both the local and impersonation
            # dispatch paths -- so consumption no longer depends on the caller's
            # optional link step. Best-effort: failure is logged, not fatal.
            mark_volume_session_consumed(target_user, session.id)

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

        rescue SessionCreateError => e
          render json: {
            status: 'error',
            code: 'SESSION_CREATE_FAILED',
            message: e.message
          }, status: :unprocessable_entity

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
        # Optional query parameter:
        #   - user: Username who owns the session. If provided and impersonation is enabled,
        #           the request is forwarded to the target user's PUN to get session details.
        def show
          target_user = params[:user]
          session_id = params[:id]
          current_pun_user = get_current_pun_user
          session_info = nil

          # Only the owner's PUN can evaluate a session's job state: the k8s
          # adapter namespaces kubectl by the calling PUN user, and ood_core
          # reports a pod it cannot see as "completed". Resolve the owner from
          # the session db when the caller omits user, and never evaluate
          # another user's session locally.
          if target_user.blank?
            session_info = find_session_by_id(session_id)
            return render_session_not_found unless session_info

            target_user = session_info[:user]
            Rails.logger.info("Admin API: Resolved session #{session_id} owner to #{target_user}")
          end

          if should_impersonate?(target_user, current_pun_user)
            Rails.logger.info("Admin API: Getting session details for #{session_id} via impersonation (user: #{target_user})")
            return show_via_impersonation(session_id, target_user)
          end

          return render_impersonation_unavailable(session_id, target_user) unless target_user == current_pun_user

          # Local path: the current PUN user owns the session
          session_info ||= find_session_by_id(session_id)
          return render_session_not_found unless session_info

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
        #
        # Optional query parameter:
        #   - user: Username who owns the session. When omitted, the owner is
        #           resolved from the session database. Cross-user requests are
        #           forwarded to the owner's PUN via impersonation.
        def connect
          target_user = params[:user]
          session_id = params[:id]
          current_pun_user = get_current_pun_user
          session_info = nil

          # Only the owner's PUN can evaluate a session's job state: the k8s
          # adapter namespaces kubectl by the calling PUN user, and ood_core
          # reports a pod it cannot see as "completed". Resolve the owner from
          # the session db when the caller omits user, and never evaluate
          # another user's session locally.
          if target_user.blank?
            session_info = find_session_by_id(session_id)
            return render_session_not_found unless session_info

            target_user = session_info[:user]
            Rails.logger.info("Admin API: Resolved session #{session_id} owner to #{target_user}")
          end

          if should_impersonate?(target_user, current_pun_user)
            Rails.logger.info("Admin API: Getting connection info for session #{session_id} via impersonation (user: #{target_user})")
            return connect_via_impersonation(session_id, target_user)
          end

          return render_impersonation_unavailable(session_id, target_user) unless target_user == current_pun_user

          # Local path: the current PUN user owns the session
          session_info ||= find_session_by_id(session_id)
          return render_session_not_found unless session_info

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
        #
        # Optional query parameter:
        #   - user: Username who owns the session. When omitted, the owner is
        #           resolved from the session database. Cross-user requests are
        #           forwarded to the owner's PUN via impersonation.
        def destroy
          target_user = params[:user]
          session_id = params[:id]
          current_pun_user = get_current_pun_user
          session_info = nil

          # Deleting from another user's PUN context would issue kubectl
          # against the wrong namespace (see connect). Resolve the owner and
          # forward cross-user deletes to the owner's PUN.
          if target_user.blank?
            session_info = find_session_by_id(session_id)
            return render_session_not_found unless session_info

            target_user = session_info[:user]
            Rails.logger.info("Admin API: Resolved session #{session_id} owner to #{target_user}")
          end

          if should_impersonate?(target_user, current_pun_user)
            Rails.logger.info("Admin API: Deleting session #{session_id} via impersonation (user: #{target_user})")
            return destroy_via_impersonation(session_id, target_user)
          end

          return render_impersonation_unavailable(session_id, target_user) unless target_user == current_pun_user

          # Local path: the current PUN user owns the session
          session_info ||= find_session_by_id(session_id)
          return render_session_not_found unless session_info

          session = session_info[:session]
          user = session_info[:user]

          begin
            # Send webhook before destroying session (FR-3)
            # This is fire-and-forget - failures don't affect session cleanup
            send_session_ended_webhook(session, 'cancelled', 'User terminated session via API')

            session.destroy
            Rails.logger.info("Admin API: Deleted session #{session_id} for user #{user}")

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

            app_data[:containers] = extract_containers(app.token)

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

        def extract_containers(app_token)
          containers_data = load_containers_yml(app_token)
          return extract_containers_from_yml(containers_data) if containers_data

          extract_containers_from_form(app_token)
        rescue => e
          Rails.logger.warn("Admin API: Could not extract containers for #{app_token}: #{e.message}")
          []
        end

        def load_containers_yml(app_token)
          app_name = app_token.split('/').last
          yml_path = File.join('/var/www/ood/apps/sys', app_name, 'containers.yml')
          return nil unless File.exist?(yml_path)

          YAML.safe_load(File.read(yml_path))
        rescue => e
          Rails.logger.warn("Admin API: Could not load containers.yml for #{app_token}: #{e.message}")
          nil
        end

        def extract_containers_from_yml(data)
          (data['containers'] || []).map do |c|
            image_name = c['image'].to_s
            versions = RegistryService.versions_for(image_name)

            {
              name: c['name'].to_s,
              label: c['label'].to_s,
              description: (c['description'] || "").to_s,
              versions: versions.map do |v|
                { tag: v[:tag], digest: v[:digest], current: v[:current] }
              end
            }
          end
        end

        def extract_containers_from_form(app_token)
          bc_app = ::BatchConnect::App.from_token(app_token)
          return [] unless bc_app && bc_app.valid?

          container_attr = bc_app.attributes.find { |a| a.id.to_s == 'container' }
          return [] unless container_attr

          options = container_attr.opts[:options] || container_attr.opts['options'] || []
          return [] if options.empty?

          descriptions = load_form_descriptions(app_token)
          options.map do |opt|
            if opt.is_a?(Array)
              val = opt[1].to_s
              { name: val, label: opt[0].to_s, description: (descriptions[val] || "").to_s, versions: [] }
            else
              val = opt.to_s
              { name: val, label: val, description: (descriptions[val] || "").to_s, versions: [] }
            end
          end
        end

        def load_form_descriptions(app_token)
          app_name = app_token.split('/').last
          form_path = File.join('/var/www/ood/apps/sys', app_name, 'form.yml')
          return {} unless File.exist?(form_path)

          form_data = YAML.safe_load(File.read(form_path), permitted_classes: [Symbol])
          container_config = form_data.dig('attributes', 'container') || {}
          container_config['container_descriptions'] || {}
        rescue => e
          Rails.logger.warn("Admin API: Could not load descriptions from #{form_path}: #{e.message}")
          {}
        end

        # List all sessions across all users
        # This requires accessing the base dataroot and iterating through user directories
        def list_all_sessions(live: true)
          sessions = []
          base_dataroot = get_base_dataroot

          return sessions unless base_dataroot.exist?

          # Iterate through potential user directories. Sessions are grouped by
          # DIRECTORY OWNER (not target_user metadata): the owner's PUN is the
          # only context that can evaluate a session's job state, and legacy
          # admin-created sessions live in the admin's dataroot with pods in
          # the admin's namespace, so they must be evaluated locally.
          base_dataroot.children.select(&:directory?).each do |user_dir|
            # Each user directory contains batch_connect data
            user_batch_connect_dir = user_dir.join('ondemand', 'data', 'sys', 'dashboard', 'batch_connect')
            next unless user_batch_connect_dir.exist?

            # Try to extract username from path or skip if not identifiable
            username = extract_username_from_path(user_dir)
            next unless username

            user_sessions = load_user_sessions_from_dataroot(user_batch_connect_dir, username)
            next if user_sessions.empty?

            sessions.concat(resolve_owner_session_entries(username, user_sessions, live: live))
          end

          sessions
        end

        # Decide how to report one owner's sessions in the unfiltered listing.
        # Only the owner's PUN can evaluate live job state (the k8s adapter
        # namespaces kubectl by the calling PUN user), so cross-user statuses
        # come from impersonation or from the session db's completed latch —
        # never from evaluating another user's session in this PUN.
        def resolve_owner_session_entries(owner, session_infos, live: true)
          # Our own sessions: this PUN is the correct evaluation context.
          return session_infos if owner == get_current_pun_user

          # All sessions latched completed: the latch is terminal and reading
          # it never touches the job adapter, so no PUN wake-up is needed.
          if session_infos.all? { |info| info[:session].cache_completed }
            return session_infos.map { |info| degraded_session_entry(info) }
          end

          if live && should_impersonate_for_list?(owner)
            live_entries = list_sessions_via_impersonation(owner)
            return merge_live_owner_entries(session_infos, live_entries) unless live_entries.nil?

            Rails.logger.warn("Admin API: Live listing for #{owner} failed; reporting cached statuses")
          end

          session_infos.map { |info| degraded_session_entry(info) }
        rescue StandardError => e
          # One bad owner must never break the whole listing.
          Rails.logger.error("Admin API: Error resolving sessions for #{owner}: #{e.class} - #{e.message}")
          session_infos.map { |info| degraded_session_entry(info) }
        end

        # Combine a successful live listing from the owner's PUN with the
        # locally scanned db files. Live entries win; local sessions absent
        # from the live response were reaped by the owner's session cleanup,
        # so keep them only if their completed latch makes the status certain.
        def merge_live_owner_entries(session_infos, live_entries)
          live_ids = live_entries.map { |entry| entry[:session].id }.to_set

          leftovers = session_infos.reject { |info| live_ids.include?(info[:session].id) }
                                   .select { |info| info[:session].cache_completed }
                                   .map { |info| degraded_session_entry(info) }

          live_entries + leftovers
        end

        # Report a session without evaluating it: 'completed' when the db's
        # completed latch is set (terminal, authoritative), 'unknown' otherwise.
        def degraded_session_entry(session_info)
          if session_info[:session].cache_completed
            session_info.merge(status: 'completed', status_source: 'cached')
          else
            session_info.merge(status: 'unknown', status_source: 'unknown')
          end
        end

        # List sessions for a specific user
        # 
        # Uses impersonation to read sessions from the target user's PUN context,
        # ensuring proper file permissions are respected.
        def list_user_sessions(username)
          # Use impersonation if enabled and target user differs from current PUN user
          if should_impersonate_for_list?(username)
            live_entries = list_sessions_via_impersonation(username)
            return live_entries unless live_entries.nil?

            Rails.logger.warn("Admin API: Live listing for #{username} failed; reporting cached statuses")
          end

          # Fallback: direct file read (only works if current user can read target's files)
          sessions = []

          user_dataroot = get_user_dataroot(username)
          batch_connect_dir = user_dataroot.join('batch_connect')
          if batch_connect_dir.exist?
            sessions.concat(load_user_sessions_from_dataroot(batch_connect_dir, username))
          end

          # Another user's sessions cannot be evaluated in this PUN's context
          # (wrong k8s namespace); report cached statuses instead.
          return sessions if username == get_current_pun_user

          sessions.map { |info| degraded_session_entry(info) }
        end

        # Check if we should use impersonation for listing sessions
        def should_impersonate_for_list?(target_user)
          return false unless PunManager.impersonation_enabled?
          return false if PunManager.internal_api_token.blank?

          current_pun_user = get_current_pun_user
          target_user != current_pun_user
        end

        # List sessions via Apache-mediated impersonation
        # Delegates to ImpersonationService for all forwarding logic.
        def list_sessions_via_impersonation(username)
          Rails.logger.info("Admin API: Listing sessions for #{username} via impersonation")
          ImpersonationService.list_sessions(username, request_host: resolve_request_host)
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
          raise SessionCreateError, e.message
        end

        # Get the current PUN user (the user whose PUN is handling this request)
        def get_current_pun_user
          OodSupport::User.new.name
        rescue StandardError
          ENV['USER'] || 'unknown'
        end

        def render_session_not_found
          render json: {
            status: 'error',
            message: 'Session not found'
          }, status: :not_found
        end

        # Render an explicit error when a cross-user request cannot be
        # forwarded to the owner's PUN. Evaluating or deleting another user's
        # session locally would target the wrong k8s namespace and misreport
        # a running session as completed.
        def render_impersonation_unavailable(session_id, target_user)
          Rails.logger.error("Admin API: Cannot act on session #{session_id} owned by #{target_user}: impersonation disabled or token missing")
          render json: {
            status: 'error',
            code: 'IMPERSONATION_UNAVAILABLE',
            message: "Session #{session_id} belongs to #{target_user}; cross-user access requires impersonation, which is not configured",
            user: target_user
          }, status: :service_unavailable
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

        # Create session via Apache-mediated PUN forwarding (impersonation).
        # Delegates to ImpersonationService for all forwarding logic.
        def create_session_via_impersonation(username, app_token, context)
          ImpersonationService.create_session(
            username, app_token, context,
            request_host: resolve_request_host,
            remote_ip: request.remote_ip
          )
        rescue PunManager::UserNotFoundError => e
          raise ImpersonationError.new('USER_NOT_FOUND', e.message, :not_found)
        end

        # Get session connection info via Apache-mediated PUN forwarding (impersonation).
        # Delegates to ImpersonationService for all forwarding logic.
        def connect_via_impersonation(session_id, target_user)
          Rails.logger.info("Admin API: Getting connection info via impersonation for session #{session_id}, user #{target_user}")

          result = ImpersonationService.get_session(session_id, target_user, request_host: resolve_request_host)

          render json: {
            status: 'success',
            user: target_user,
            session_status: result.dig('session', 'status'),
            connection: result['connection'],
            connection_url: result['connection_url']
          }

        rescue PunManager::UserNotFoundError => e
          Rails.logger.error("Admin API: Impersonation failed for connect - #{e.message}")
          render json: { status: 'error', message: e.message }, status: :not_found
        rescue ImpersonationError => e
          render json: { status: 'error', message: e.message }, status: e.http_status
        rescue StandardError => e
          Rails.logger.error("Admin API: Error in connect impersonation: #{e.class} - #{e.message}")
          render json: { status: 'error', message: e.message }, status: :internal_server_error
        end

        # Get session details via Apache-mediated PUN forwarding (impersonation).
        # Delegates to ImpersonationService for all forwarding logic.
        def show_via_impersonation(session_id, target_user)
          result = ImpersonationService.get_session(session_id, target_user, request_host: resolve_request_host)

          session_data = result['session'] || {}
          session_data['connect_url'] = result['connection_url']

          render json: {
            status: 'success',
            session: session_data
          }

        rescue PunManager::UserNotFoundError => e
          Rails.logger.error("Admin API: Impersonation failed for show - #{e.message}")
          render json: { status: 'error', message: e.message }, status: :not_found
        rescue ImpersonationError => e
          render json: { status: 'error', message: e.message }, status: e.http_status
        rescue StandardError => e
          Rails.logger.error("Admin API: Error in show impersonation: #{e.class} - #{e.message}")
          render json: { status: 'error', message: e.message }, status: :internal_server_error
        end

        # Delete session via Apache-mediated PUN forwarding (impersonation).
        # Delegates to ImpersonationService for all forwarding logic.
        def destroy_via_impersonation(session_id, target_user)
          ImpersonationService.delete_session(session_id, target_user, request_host: resolve_request_host)

          Rails.logger.info("Admin API: Deleted session #{session_id} for user #{target_user} via impersonation")

          render json: {
            status: 'success',
            message: 'Session deleted',
            user: target_user
          }

        rescue PunManager::UserNotFoundError => e
          Rails.logger.error("Admin API: Impersonation failed for delete - #{e.message}")
          render json: { status: 'error', message: e.message }, status: :not_found
        rescue ImpersonationError => e
          render json: { status: 'error', message: e.message }, status: e.http_status
        rescue StandardError => e
          Rails.logger.error("Admin API: Error in delete impersonation: #{e.class} - #{e.message}")
          render json: { status: 'error', message: e.message }, status: :internal_server_error
        end

        # Resolve the Host header value for forwarding requests through Apache.
        # Falls back to OOD_SERVER_NAME env var or 'localhost'.
        def resolve_request_host
          self.request.host_with_port
        rescue NoMethodError
          ENV['OOD_SERVER_NAME'] || 'localhost'
        end

        # NOTE: forward_*_via_apache, handle_*_impersonation_response,
        # parse_json_response, and log_impersonation_* methods have been
        # extracted to ImpersonationService (app/services/impersonation_service.rb)

        # Legacy session creation - creates in admin's dataroot with target_user metadata
        def create_session_locally(username, app, context)
          session = ::BatchConnect::Session.new
          save_result = session.save(app: app, context: context)
          
          unless save_result
            detail = session.errors.full_messages.join('; ')
            Rails.logger.error("Admin API: Session save failed for user #{username}: #{detail}")
            raise SessionCreateError, detail.presence || 'Session save failed'
          end

          # Store target_user in the user_defined_context file
          store_target_user_metadata(session, username)

          Rails.logger.info("Admin API: Created session #{session.id} for target user #{username}")
          session
        end

        # Error class when session creation fails (stage/submit/local error)
        class SessionCreateError < StandardError; end

        # ImpersonationError and ImpersonatedSession are defined in
        # app/services/impersonation_error.rb and impersonated_session.rb
        # (loaded via require_relative above)

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

        # Validate that storage_path + volume_session_id correspond to a fresh,
        # owned, not-yet-consumed Volume API mount handle (spec 049, FR-002/003/004).
        #
        # Returns an error message string describing the cause (without leaking
        # another user's data), or nil when the handle is valid.
        #
        # @param target_user [String] user the session is launched for
        # @param storage_path [String] the mount location supplied by the caller
        # @param volume_session_id [String, nil] the mount handle id
        # @return [String, nil]
        def validate_volume_session(target_user, storage_path, volume_session_id)
          return 'missing volume_session_id for storage_path' if volume_session_id.blank?

          begin
            session = VolumeApiClient.get_session(volume_session_id)
          rescue VolumeApiClient::VolumeApiError => e
            Rails.logger.error("Admin API: could not validate volume session #{volume_session_id}: #{e.message}")
            return 'cannot validate codespace: volume service unavailable'
          end

          return 'volume session not found or already ended' if session.nil?

          owner = session['user_id'] || session[:user_id]
          mount_path = session['mount_path'] || session[:mount_path]
          state = session['state'] || session[:state]
          linked = session['container_session_id'] || session[:container_session_id]

          return 'volume session does not belong to target_user' unless owner == target_user
          return 'storage_path does not match the prepared volume session' unless mount_path == storage_path
          return 'volume session already in use' unless state == 'ready' && linked.nil?

          # Stash the validated handle so create can mark it consumed after a
          # successful launch (needs its volume_id). See mark_volume_session_consumed.
          @validated_volume_session = session
          nil # Valid
        end

        # Mark the validated mount handle as consumed by the just-launched session
        # (spec 049, US1#5): a successful launch must make its volume_session_id
        # non-reusable, independent of the optional caller-side link step. Uses the
        # handle validated in validate_volume_session (for its volume_id) and links
        # it to the new running session, flipping it to in_use. Best-effort: logged,
        # never fatal -- a launched session is not rolled back over this.
        #
        # @param target_user [String] owner of the handle (X-User-ID for the call)
        # @param container_session_id [String] the launched OOD session id
        def mark_volume_session_consumed(target_user, container_session_id)
          handle = @validated_volume_session
          return if handle.blank?

          volume_id = handle['volume_id'] || handle[:volume_id]
          volume_session_id = handle['id'] || handle[:id]
          return if volume_id.blank? || volume_session_id.blank?

          VolumeApiClient.mark_consumed(target_user, volume_id, volume_session_id, container_session_id)
        rescue VolumeApiClient::VolumeApiError => e
          Rails.logger.error("Admin API: could not mark volume session #{volume_session_id} consumed: #{e.message}")
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
