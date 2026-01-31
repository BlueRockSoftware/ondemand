# frozen_string_literal: true

require 'httparty'
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
      # Check if volume_session_id is present - if not, skip webhook
      volume_session_id = session_volume_id(session)
      return unless volume_session_id.present?

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

    # Extract volume_session_id from session info
    #
    # @param session [BatchConnect::Session] The session
    # @return [String, nil] The volume session ID if present
    def session_volume_id(session)
      # Try multiple possible locations for the volume_session_id
      info = session.info.to_h rescue {}
      
      info[:volume_session_id] || 
        info['volume_session_id'] ||
        (session.respond_to?(:volume_session_id) ? session.volume_session_id : nil)
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

      payload
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
    #
    # @param volume_api_url [String] The base URL of the Volume API
    # @param payload [Hash] The webhook payload
    # @param session_id [String] The session ID (for logging)
    # @return [void]
    def send_webhook_sync(volume_api_url, payload, session_id)
      webhook_url = "#{volume_api_url.chomp('/')}/api/v1/webhooks/session-ended"
      
      headers = {
        'Content-Type' => 'application/json',
        'Accept' => 'application/json'
      }

      # Add bearer token if configured
      volume_api_token = ENV['VOLUME_API_TOKEN']
      headers['Authorization'] = "Bearer #{volume_api_token}" if volume_api_token.present?

      Rails.logger.info("VolumeWebhookService: Sending session-ended webhook for session #{session_id} " \
                       "to #{webhook_url}")

      response = HTTParty.post(
        webhook_url,
        body: payload.to_json,
        headers: headers,
        timeout: WEBHOOK_TIMEOUT
      )

      if response.success?
        Rails.logger.info("VolumeWebhookService: Webhook sent successfully for session #{session_id} " \
                         "(status: #{response.code})")
      else
        Rails.logger.error("VolumeWebhookService: Webhook failed for session #{session_id} " \
                          "(status: #{response.code}, body: #{response.body})")
      end
    rescue HTTParty::Error => e
      Rails.logger.error("VolumeWebhookService: HTTP error sending webhook for session #{session_id}: " \
                        "#{e.class} - #{e.message}")
    rescue Timeout::Error => e
      Rails.logger.error("VolumeWebhookService: Timeout sending webhook for session #{session_id}: " \
                        "#{e.message}")
    rescue StandardError => e
      Rails.logger.error("VolumeWebhookService: Error sending webhook for session #{session_id}: " \
                        "#{e.class} - #{e.message}")
    end
  end
end
