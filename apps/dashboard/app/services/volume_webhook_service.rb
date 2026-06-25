# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

# Service class for sending webhooks to the Volume API when sessions terminate.
# This service is fire-and-forget: webhook failures are logged but do not
# block session cleanup.
#
# Usage:
#   VolumeWebhookService.send_session_ended(session, 'completed',
#     exit_code: 0,
#     exit_reason: 'User terminated session'
#   )
#
class VolumeWebhookService
  # Timeout for webhook HTTP requests (seconds)
  WEBHOOK_TIMEOUT = 5

  # Valid exit status values
  VALID_EXIT_STATUSES = %w[completed failed timeout cancelled unknown].freeze

  class << self
    # Send a session-ended webhook to the Volume API
    #
    # @param session [BatchConnect::Session] The session that ended
    # @param exit_status [String] How the session ended (completed, failed, timeout, cancelled, unknown)
    # @param exit_code [Integer, nil] Container exit code if available (0-255)
    # @param exit_reason [String, nil] Human-readable explanation of why session ended
    #
    # @return [void] This method is fire-and-forget
    def send_session_ended(session, exit_status, exit_code: nil, exit_reason: nil)
      # Fire for codespace sessions only. Identify one by either the mount-handle
      # id or the storage_path recorded at launch (checked in both session.info
      # and the persisted user_context). The webhook always carries
      # container_session_id (= session.id), which the launch linked onto the
      # handle, so the Volume API can reclaim by that even when volume_session_id
      # is not recoverable here (spec 049, FR-007).
      volume_session_id = session_volume_id(session)
      return unless volume_session_id.present? || session_storage_path(session).present?

      # Check if Volume API URL is configured
      volume_api_url = ENV['VOLUME_API_URL']
      unless volume_api_url.present?
        Rails.logger.debug('VolumeWebhookService: VOLUME_API_URL not configured, skipping webhook')
        return
      end

      # Validate exit_status
      unless VALID_EXIT_STATUSES.include?(exit_status)
        Rails.logger.warn("VolumeWebhookService: Invalid exit_status '#{exit_status}', using 'unknown'")
        exit_status = 'unknown'
      end

      # Build webhook payload
      payload = build_payload(session, volume_session_id, exit_status, exit_code, exit_reason)

      # Send webhook asynchronously
      send_webhook_async(volume_api_url, payload, session.id)
    end

    # Map OOD session status to exit status enum
    #
    # @param session [BatchConnect::Session] The session to check
    # @return [String] The exit status
    def determine_exit_status(session)
      if session.completed?
        'completed'
      elsif session_failed?(session)
        'failed'
      else
        'unknown'
      end
    end

    private

    # Extract volume_session_id from the session. Checks session.info and the
    # persisted user_context (where the launch stores the codespace mount params),
    # since info does not reliably carry it through the impersonated lifecycle.
    #
    # @param session [BatchConnect::Session] The session
    # @return [String, nil] The volume session ID if present
    def session_volume_id(session)
      info = session.info.to_h rescue {}
      ctx = session.user_context rescue {}

      info[:volume_session_id] ||
        info['volume_session_id'] ||
        (ctx['volume_session_id'] if ctx.respond_to?(:[])) ||
        (session.respond_to?(:volume_session_id) ? session.volume_session_id : nil)
    end

    # Codespace marker: the storage_path recorded at launch (session.info or the
    # persisted user_context). Its presence means the session mounted a codespace
    # and a handle must be reclaimed, even if volume_session_id isn't recoverable.
    #
    # @param session [BatchConnect::Session] The session
    # @return [String, nil] The storage path if present
    def session_storage_path(session)
      info = session.info.to_h rescue {}
      ctx = session.user_context rescue {}

      info[:storage_path] ||
        info['storage_path'] ||
        (ctx['storage_path'] if ctx.respond_to?(:[]))
    end

    # Check if session failed (has error status or non-zero exit code)
    #
    # @param session [BatchConnect::Session] The session
    # @return [Boolean] True if session failed
    def session_failed?(session)
      return true if session.respond_to?(:status) && session.status == 'failed'
      
      # Check for error in job info
      info = session.info.to_h rescue {}
      info[:error].present? || info['error'].present?
    end

    # Build the webhook payload
    #
    # @param session [BatchConnect::Session] The session
    # @param volume_session_id [String] The volume session ID
    # @param exit_status [String] The exit status
    # @param exit_code [Integer, nil] The exit code
    # @param exit_reason [String, nil] The exit reason
    # @return [Hash] The webhook payload
    def build_payload(session, volume_session_id, exit_status, exit_code, exit_reason)
      payload = {
        volume_session_id: volume_session_id,
        container_session_id: session.id,
        exit_status: exit_status,
        ended_at: Time.now.utc.iso8601
      }

      # Add optional fields if present
      payload[:exit_code] = exit_code.to_i if exit_code.present?
      payload[:exit_reason] = exit_reason.to_s if exit_reason.present?

      # Immutable image digest the session ran on, for lock-time reproducibility
      # capture (spec 046, FR-008). Optional; absent => Volume API leaves the
      # session's image_digest NULL (recorded as unverified at lock).
      image_digest = session_image_digest(session)
      payload[:image_digest] = image_digest if image_digest.present?

      payload
    end

    # Extract the running image digest (repo@sha256:...) from the session's k8s
    # pod status. The OOD Kubernetes adapter surfaces the pod via session.info;
    # `status.containerStatuses[].imageID` is the immutable digest reference.
    # Defensive across the info shapes the adapter may return.
    #
    # @param session [BatchConnect::Session] The session
    # @return [String, nil] repo@sha256:... digest if resolvable
    def session_image_digest(session)
      info = session.info.to_h rescue {}
      # Explicit field if a future adapter version provides it directly.
      digest = info[:image_digest] || info['image_digest']
      return digest if digest.present?

      native = info[:native] || info['native'] || {}
      statuses =
        native.dig(:status, :containerStatuses) ||
        native.dig('status', 'containerStatuses') ||
        []
      Array(statuses).each do |cs|
        image_id = (cs[:imageID] || cs['imageID']).to_s
        # imageID is typically "<repo>@sha256:<hex>" (may carry a docker-pullable
        # prefix); keep only the canonical "<repo>@sha256:<hex>" portion.
        if image_id =~ %r{([a-z0-9._/-]+@sha256:[a-f0-9]{64})}
          return Regexp.last_match(1)
        end
      end
      nil
    rescue StandardError => e
      Rails.logger.warn("VolumeWebhookService: could not resolve image digest: #{e.class} - #{e.message}")
      nil
    end

    # Send the webhook asynchronously in a background thread
    #
    # @param volume_api_url [String] The base URL of the Volume API
    # @param payload [Hash] The webhook payload
    # @param session_id [String] The session ID (for logging)
    # @return [void]
    def send_webhook_async(volume_api_url, payload, session_id)
      Thread.new do
        send_webhook_sync(volume_api_url, payload, session_id)
      end
    end

    # Send the webhook synchronously (called from background thread)
    # Uses Net::HTTP (built into Ruby) instead of external gems
    #
    # @param volume_api_url [String] The base URL of the Volume API
    # @param payload [Hash] The webhook payload
    # @param session_id [String] The session ID (for logging)
    # @return [void]
    def send_webhook_sync(volume_api_url, payload, session_id)
      webhook_url = "#{volume_api_url.chomp('/')}/api/v1/webhooks/session-ended"
      uri = URI.parse(webhook_url)

      Rails.logger.info("VolumeWebhookService: Sending session-ended webhook for session #{session_id} " \
                       "to #{webhook_url}")

      # Create HTTP connection
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.open_timeout = WEBHOOK_TIMEOUT
      http.read_timeout = WEBHOOK_TIMEOUT
      
      # Don't verify SSL for internal cluster communication
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?

      # Build request
      request = Net::HTTP::Post.new(uri.path)
      request['Content-Type'] = 'application/json'
      request['Accept'] = 'application/json'

      # Add bearer token if configured. Prefer OOD_VOLUME_API_TOKEN: the PUN env
      # is built across a sudo boundary that keeps only OOD_* vars, so the bare
      # VOLUME_API_TOKEN is nil in the Rails worker and the teardown webhook
      # would post unauthenticated (401, reclamation lost). Fall back to the
      # bare name for non-PUN contexts (e.g. tests).
      volume_api_token = ENV['OOD_VOLUME_API_TOKEN'].presence || ENV['VOLUME_API_TOKEN']
      request['Authorization'] = "Bearer #{volume_api_token}" if volume_api_token.present?

      request.body = payload.to_json

      # Send request
      response = http.request(request)

      if response.is_a?(Net::HTTPSuccess)
        Rails.logger.info("VolumeWebhookService: Webhook sent successfully for session #{session_id} " \
                         "(status: #{response.code})")
      else
        Rails.logger.error("VolumeWebhookService: Webhook failed for session #{session_id} " \
                          "(status: #{response.code}, body: #{response.body})")
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      Rails.logger.error("VolumeWebhookService: Timeout sending webhook for session #{session_id}: " \
                        "#{e.message}")
    rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
      Rails.logger.error("VolumeWebhookService: Connection error sending webhook for session #{session_id}: " \
                        "#{e.class} - #{e.message}")
    rescue StandardError => e
      Rails.logger.error("VolumeWebhookService: Error sending webhook for session #{session_id}: " \
                        "#{e.class} - #{e.message}")
    end
  end
end
