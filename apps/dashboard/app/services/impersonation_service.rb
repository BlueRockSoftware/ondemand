# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'ostruct'
require_relative 'pun_manager'
require_relative 'impersonation_error'
require_relative 'impersonated_session'

# Centralized service for Apache-mediated PUN (Per-User Nginx) impersonation.
#
# Provides a single point of entry for all impersonation operations:
# creating, listing, retrieving, and deleting Batch Connect sessions
# in a target user's PUN context.
#
# Architecture:
#   Admin API Controller -> ImpersonationService -> Apache (localhost:80)
#     -> api_auth.lua validates internal token, sets REMOTE_USER
#     -> pun_proxy.lua starts target PUN if needed
#     -> Target user's PUN handles request
#
# The service returns data hashes; controllers handle rendering.
# Raises ImpersonationError on failure.
class ImpersonationService
  INTERNAL_API_PATH = '/pun/sys/dashboard/internal/batch_connect/sessions'

  class << self
    # Create a Batch Connect session in the target user's PUN context.
    # @return [ImpersonatedSession]
    # @raise [ImpersonationError, PunManager::UserNotFoundError]
    def create_session(username, app_token, context, request_host:, remote_ip: nil)
      validate_prerequisites!
      log_impersonation('attempt', action: 'create_session', target_user: username, remote_ip: remote_ip)
      PunManager.validate_user(username)

      payload = build_create_payload(app_token, context)
      response = forward_request(:post, username, INTERNAL_API_PATH,
                                 body: payload, request_host: request_host, read_timeout: 60)

      result = parse_create_response(response, username, remote_ip)
      log_impersonation('success', action: 'create_session', target_user: username,
                                   session_id: result.id, remote_ip: remote_ip)
      result
    rescue PunManager::UserNotFoundError => e
      log_impersonation('failure', action: 'create_session', target_user: username,
                                   error_code: 'USER_NOT_FOUND', error_message: e.message, remote_ip: remote_ip)
      raise
    end

    # List sessions in the target user's PUN context.
    # @return [Array<Hash>] Session info hashes [{ user: String, session: OpenStruct }], or [] on failure
    # Returns an array of session-info hashes on success (possibly empty —
    # the target PUN legitimately reported no sessions), or nil when the
    # listing could not be obtained (unknown user, PUN unreachable, token not
    # configured). Callers must treat nil as "status unknown", not "no
    # sessions".
    def list_sessions(username, request_host:)
      validate_prerequisites!
      PunManager.validate_user(username)
      response = forward_request(:get, username, INTERNAL_API_PATH, request_host: request_host)
      parse_list_response(response, username)
    rescue PunManager::UserNotFoundError => e
      Rails.logger.error("ImpersonationService: List failed - #{e.message}")
      nil
    rescue ImpersonationError => e
      Rails.logger.error("ImpersonationService: List failed - #{e.message}")
      nil
    rescue Errno::ECONNREFUSED, Net::OpenTimeout, Net::ReadTimeout, SocketError => e
      Rails.logger.error("ImpersonationService: Error listing sessions: #{e.message}")
      nil
    end

    # Get session details (including connection info) from the target user's PUN.
    # @return [Hash] Parsed session data
    # @raise [ImpersonationError, PunManager::UserNotFoundError]
    def get_session(session_id, username, request_host:)
      validate_prerequisites!
      PunManager.validate_user(username)
      path = "#{INTERNAL_API_PATH}/#{session_id}"
      response = forward_request(:get, username, path, request_host: request_host)
      parse_simple_response(response, context: "get session #{session_id}")
    end

    # Delete a session in the target user's PUN context.
    # @return [Hash] Parsed response data
    # @raise [ImpersonationError, PunManager::UserNotFoundError]
    def delete_session(session_id, username, request_host:)
      validate_prerequisites!
      PunManager.validate_user(username)
      path = "#{INTERNAL_API_PATH}/#{session_id}"
      response = forward_request(:delete, username, path, request_host: request_host)
      parse_simple_response(response, context: "delete session #{session_id}")
    end

    # Unified HTTP forwarding through Apache with impersonation headers.
    # Replaces 4 separate forward_*_via_apache methods.
    #
    # Apache handles token validation (api_auth.lua), REMOTE_USER setting,
    # PUN startup (pun_proxy.lua), and routing to the target PUN.
    def forward_request(method, target_user, path, body: nil, request_host: nil, read_timeout: 30)
      uri = URI("http://127.0.0.1#{path}")

      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = 10
      http.read_timeout = read_timeout

      request = build_http_request(method, uri.path)
      request['Accept'] = 'application/json'
      request['Host'] = request_host || ENV['OOD_SERVER_NAME'] || 'localhost'
      request['X-Impersonate-User'] = target_user
      request['X-Internal-Token'] = PunManager.internal_api_token

      if body && method == :post
        request['Content-Type'] = 'application/json'
        request.body = body.to_json
      end

      Rails.logger.debug("ImpersonationService: Forwarding #{method.upcase} to Apache for user #{target_user}")
      response = http.request(request)
      Rails.logger.debug("ImpersonationService: Apache response: #{response.code} #{response.message}")
      response
    end

    # Log an impersonation event for audit purposes.
    # @param event_type [String] 'attempt', 'success', or 'failure'
    def log_impersonation(event_type, action:, target_user:, admin_user: nil, session_id: nil,
                          error_code: nil, error_message: nil, remote_ip: nil)
      entry = {
        event: "admin_api_impersonation_#{event_type}",
        action: action,
        admin_user: admin_user || current_pun_user,
        target_user: target_user,
        timestamp: Time.now.utc.iso8601,
        remote_ip: remote_ip
      }
      entry[:session_id] = session_id if session_id
      entry[:error_code] = error_code if error_code
      entry[:error_message] = error_message if error_message

      level = event_type == 'failure' ? :warn : :info
      Rails.logger.public_send(level, entry.to_json)
    end

    private

    # Validate internal API token is configured.
    def validate_prerequisites!
      return unless PunManager.internal_api_token.blank?

      raise ImpersonationError.new(
        'TOKEN_NOT_CONFIGURED',
        'Internal API token is not configured (OOD_INTERNAL_API_TOKEN)',
        :service_unavailable
      )
    end

    # Build Net::HTTP request for the given method.
    def build_http_request(method, path)
      case method
      when :get    then Net::HTTP::Get.new(path)
      when :post   then Net::HTTP::Post.new(path)
      when :delete then Net::HTTP::Delete.new(path)
      else raise ArgumentError, "Unsupported HTTP method: #{method}"
      end
    end

    # Build JSON payload for session creation, including volume params.
    def build_create_payload(app_token, context)
      payload = {
        app_token: app_token,
        context: context.respond_to?(:to_h) ? context.to_h : context.attributes
      }

      if context.respond_to?(:attributes)
        attrs = context.attributes
        payload[:storage_path] = attrs['storage_path'] if attrs['storage_path'].present?
        payload[:volume_session_id] = attrs['volume_session_id'] if attrs['volume_session_id'].present?
      end

      payload
    end

    # Parse create response: returns ImpersonatedSession or raises ImpersonationError.
    def parse_create_response(response, username, remote_ip)
      unless response.is_a?(Net::HTTPSuccess)
        error_data = parse_json_response(response.body)
        error_msg = error_data['message'].presence || "Internal API returned #{response.code}"

        if error_data['errors'].present? && error_data['errors'].is_a?(Array)
          error_msg = "#{error_msg}: #{error_data['errors'].join('; ')}"
        end

        if error_msg == "Internal API returned #{response.code}" && response.body.present?
          snippet = response.body.to_s[0, 500].gsub(/\s+/, ' ')
          error_msg = "#{error_msg} (#{snippet})"
        end

        error_code = error_data['code'].presence || 'IMPERSONATION_FAILED'
        Rails.logger.error("ImpersonationService: Create request failed: #{error_msg}")
        log_impersonation('failure', action: 'create_session', target_user: username,
                                     error_code: error_code, error_message: error_msg, remote_ip: remote_ip)
        raise ImpersonationError.new(error_code, error_msg, map_http_status(response.code.to_i))
      end

      data = parse_json_response(response.body)
      unless data && data['status'] == 'success'
        error_msg = data&.dig('message') || 'Impersonation response missing success status'
        if data&.dig('errors').present? && data['errors'].is_a?(Array)
          error_msg = "#{error_msg}: #{data['errors'].join('; ')}"
        end
        Rails.logger.error("ImpersonationService: #{error_msg}")
        log_impersonation('failure', action: 'create_session', target_user: username,
                                     error_code: 'INVALID_RESPONSE', error_message: error_msg, remote_ip: remote_ip)
        raise ImpersonationError.new('INVALID_RESPONSE', error_msg, :bad_gateway)
      end

      ImpersonatedSession.new(data)
    end

    # Parse list response: returns array of session-info hashes with OpenStruct
    # sessions, or nil when the response is not a successful listing.
    def parse_list_response(response, username)
      unless response.is_a?(Net::HTTPSuccess)
        Rails.logger.error("ImpersonationService: List failed: #{response.code} #{response.message}")
        return nil
      end

      data = parse_json_response(response.body)
      unless data && data['status'] == 'success'
        Rails.logger.error("ImpersonationService: List response missing success status")
        return nil
      end

      (data['sessions'] || []).map do |sd|
        session = OpenStruct.new(id: sd['id'], job_id: sd['job_id'], title: sd['title'],
                                 created_at: sd['created_at'], cluster_id: sd['cluster_id'],
                                 token: sd['token'])

        session.define_singleton_method(:user_context) { { 'project' => sd['project'] } }

        status = sd['status']
        session.define_singleton_method(:completed?) { status == 'completed' }
        session.define_singleton_method(:running?) { status == 'running' }
        session.define_singleton_method(:queued?) { status == 'queued' }

        { user: username, session: session }
      end
    end

    # Parse a simple response (get/delete). Returns data hash or raises ImpersonationError.
    def parse_simple_response(response, context:)
      unless response.is_a?(Net::HTTPSuccess)
        error_data = parse_json_response(response.body)
        error_msg = error_data['message'].presence || "Request failed"
        Rails.logger.warn("ImpersonationService: #{context} failed: #{error_msg}")
        raise ImpersonationError.new(
          error_data['code'].presence || 'IMPERSONATION_FAILED',
          error_msg,
          map_http_status(response.code.to_i)
        )
      end

      data = parse_json_response(response.body)

      unless data.is_a?(Hash) && data['status'].present?
        content_type = response['Content-Type'] || 'unknown'
        snippet = response.body.to_s[0, 200].gsub(/\s+/, ' ')
        Rails.logger.error("ImpersonationService: #{context} returned non-JSON or invalid response " \
                           "(Content-Type: #{content_type}): #{snippet}")
        raise ImpersonationError.new(
          'INVALID_RESPONSE',
          "Target PUN returned non-API response for #{context}",
          :bad_gateway
        )
      end

      unless data['status'] == 'success'
        error_msg = data['message'].presence || "#{context} failed"
        raise ImpersonationError.new(
          data['code'].presence || 'IMPERSONATION_FAILED',
          error_msg,
          :bad_gateway
        )
      end

      data
    end

    # Safely parse JSON response body, returns {} on failure.
    def parse_json_response(body)
      return {} if body.nil? || body.empty?
      JSON.parse(body)
    rescue JSON::ParserError => e
      Rails.logger.warn("ImpersonationService: Failed to parse JSON: #{e.message}")
      {}
    end

    # Map HTTP status codes to Rails status symbols.
    def map_http_status(code)
      case code
      when 401 then :unauthorized
      when 404 then :not_found
      when 422 then :unprocessable_entity
      when 503 then :service_unavailable
      when 504 then :gateway_timeout
      else :bad_gateway
      end
    end

    # Get the current PUN user for audit logging.
    def current_pun_user
      OodSupport::User.new.name
    rescue NameError, ArgumentError, Errno::ENOENT
      ENV['USER'] || 'unknown'
    end
  end
end
