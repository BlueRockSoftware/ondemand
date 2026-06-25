# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'openssl'

# Read-only client for the Volume API.
#
# Used by the Admin API to validate a codespace mount handle (volume session)
# before launching a session, so a stale, forged, or mismatched value cannot be
# mounted silently (spec 049). Mirrors the HTTP / env / TLS conventions of
# VolumeWebhookService; the only method is a single admin lookup.
#
# Configuration (same env as VolumeWebhookService):
#   - VOLUME_API_URL          base URL of the Volume API
#   - OOD_VOLUME_API_TOKEN    service bearer token (preferred; survives the
#                             OOD_*-only PUN env scrub), falling back to
#                             VOLUME_API_TOKEN outside the PUN (e.g. tests)
class VolumeApiClient
  # Timeout for the validation request (seconds). Short: this is on the session
  # create path and must fail fast rather than hang a launch.
  HTTP_TIMEOUT = 5

  # Raised when the Volume API is unconfigured or cannot be reached. The caller
  # maps this to "cannot validate" rather than mounting unvalidated storage.
  class VolumeApiError < StandardError; end

  class << self
    # Look up a volume session (mount handle) by id.
    #
    # @param volume_session_id [String] the Volume API session id
    # @return [Hash, nil] the parsed session record, or nil when not found (404)
    # @raise [VolumeApiError] when the Volume API is unconfigured/unreachable
    def get_session(volume_session_id)
      base_url = ENV['VOLUME_API_URL']
      raise VolumeApiError, 'VOLUME_API_URL not configured' unless base_url.present?

      uri = URI.parse("#{base_url.chomp('/')}/api/v1/admin/sessions/#{volume_session_id}")
      http = build_http(uri)

      request = Net::HTTP::Get.new(uri.request_uri)
      request['Accept'] = 'application/json'
      # Prefer the OOD_-prefixed name: the admin/api PUN environment is built
      # across a sudo boundary whose env_keep preserves only OOD_* vars, so a
      # bare VOLUME_API_TOKEN is scrubbed to nil in the Rails worker and the
      # lookup goes out unauthenticated (401 -> validation fails closed). The
      # chart also exports OOD_VOLUME_API_TOKEN. Fall back to the bare name for
      # non-PUN contexts (e.g. tests).
      token = ENV['OOD_VOLUME_API_TOKEN'].presence || ENV['VOLUME_API_TOKEN']
      request['Authorization'] = "Bearer #{token}" if token.present?

      response = http.request(request)

      case response
      when Net::HTTPSuccess
        JSON.parse(response.body)
      when Net::HTTPNotFound
        nil
      else
        raise VolumeApiError, "Volume API returned #{response.code}"
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise VolumeApiError, "Volume API timeout: #{e.message}"
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError => e
      raise VolumeApiError, "Volume API unreachable: #{e.class} - #{e.message}"
    rescue JSON::ParserError => e
      raise VolumeApiError, "Volume API returned invalid JSON: #{e.message}"
    end

    # Mark a mount handle as consumed by a running session (spec 049, US1#5):
    # links it to container_session_id and flips it to `in_use`, so a second
    # launch reusing the same volume_session_id is rejected. The OOD create
    # path calls this server-side after a successful launch, so consumption no
    # longer depends on the caller performing the optional link step.
    #
    # PATCH /api/v1/volumes/{volume_id}/sessions/{volume_session_id} is
    # user-scoped (X-User-ID + ownership check), so the handle's owner is passed
    # as user_id. Best-effort: the caller logs failures rather than rolling back
    # a launched session.
    def mark_consumed(user_id, volume_id, volume_session_id, container_session_id)
      base_url = ENV['VOLUME_API_URL']
      raise VolumeApiError, 'VOLUME_API_URL not configured' unless base_url.present?

      uri = URI.parse("#{base_url.chomp('/')}/api/v1/volumes/#{volume_id}/sessions/#{volume_session_id}")
      http = build_http(uri)

      request = Net::HTTP::Patch.new(uri.request_uri)
      request['Content-Type'] = 'application/json'
      request['Accept'] = 'application/json'
      token = ENV['OOD_VOLUME_API_TOKEN'].presence || ENV['VOLUME_API_TOKEN']
      request['Authorization'] = "Bearer #{token}" if token.present?
      request['X-User-ID'] = user_id
      request.body = { container_session_id: container_session_id }.to_json

      response = http.request(request)
      return JSON.parse(response.body) if response.is_a?(Net::HTTPSuccess)

      raise VolumeApiError, "Volume API returned #{response.code}"
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      raise VolumeApiError, "Volume API timeout: #{e.message}"
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError => e
      raise VolumeApiError, "Volume API unreachable: #{e.class} - #{e.message}"
    rescue JSON::ParserError => e
      raise VolumeApiError, "Volume API returned invalid JSON: #{e.message}"
    end

    private

    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      # Internal cluster TLS, same as VolumeWebhookService.
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?
      http.open_timeout = HTTP_TIMEOUT
      http.read_timeout = HTTP_TIMEOUT
      http
    end
  end
end
