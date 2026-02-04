# frozen_string_literal: true

require 'open3'
require 'etc'

# Manages PUN (Per-User Nginx) lifecycle for user impersonation
# 
# This service handles:
# - Validating target users exist
# - Starting target user's PUN if not running
# - Waiting for PUN socket to be ready
# - Forwarding requests to target user's PUN
class PunManager
  # Custom errors
  class PunError < StandardError; end
  class UserNotFoundError < PunError; end
  class PunStartupError < PunError; end
  class PunTimeoutError < PunError; end
  class PunConnectionError < PunError; end

  # Default configuration
  DEFAULT_STARTUP_TIMEOUT = 30
  SOCKET_CHECK_INTERVAL = 0.5
  NGINX_STAGE_PATH = '/opt/ood/nginx_stage/sbin/nginx_stage'

  # Mutex for preventing race conditions during PUN startup
  @@startup_locks = {}
  @@locks_mutex = Mutex.new

  class << self
    # Get PUN socket path for a user
    #
    # @param username [String] System username
    # @return [String] Path to PUN socket
    def socket_path(username)
      "/var/run/ondemand-nginx/#{username}/passenger.sock"
    end

    # Get PUN PID path for a user
    #
    # @param username [String] System username
    # @return [String] Path to PUN PID file
    def pid_path(username)
      "/var/run/ondemand-nginx/#{username}/passenger.pid"
    end

    # Check if a user's PUN is currently running
    #
    # @param username [String] System username
    # @return [Boolean] true if PUN socket exists and is a socket
    def running?(username)
      path = socket_path(username)
      File.exist?(path) && File.socket?(path)
    end

    # Validate that a user exists in the system (LDAP/NSS)
    #
    # @param username [String] System username
    # @return [Struct::Passwd] User's passwd entry
    # @raise [UserNotFoundError] if user doesn't exist
    def validate_user(username)
      Etc.getpwnam(username)
    rescue ArgumentError
      raise UserNotFoundError, "User not found: #{username}"
    end

    # Ensure a user's PUN is running, starting it if necessary
    #
    # @param username [String] System username
    # @param timeout [Integer] Seconds to wait for PUN to start
    # @return [String] Path to PUN socket
    # @raise [UserNotFoundError] if user doesn't exist
    # @raise [PunStartupError] if PUN fails to start
    # @raise [PunTimeoutError] if PUN doesn't become ready in time
    def ensure_running(username, timeout: nil)
      timeout ||= startup_timeout

      # Validate user exists first
      validate_user(username)

      # If already running, return socket path
      if running?(username)
        Rails.logger.debug("PunManager: PUN already running for #{username}")
        return socket_path(username)
      end

      # Get or create lock for this user to prevent race conditions
      lock = get_startup_lock(username)

      lock.synchronize do
        # Double-check after acquiring lock
        if running?(username)
          Rails.logger.debug("PunManager: PUN started by another thread for #{username}")
          return socket_path(username)
        end

        Rails.logger.info("PunManager: Starting PUN for #{username}")
        start_pun(username)
        wait_for_socket(username, timeout)
      end

      socket_path(username)
    end

    # Start a user's PUN via nginx_stage
    #
    # @param username [String] System username
    # @raise [PunStartupError] if nginx_stage command fails
    def start_pun(username)
      cmd = "sudo #{NGINX_STAGE_PATH} pun -u #{username}"
      
      stdout, stderr, status = Open3.capture3(cmd)

      unless status.success?
        Rails.logger.error("PunManager: Failed to start PUN for #{username}: #{stderr}")
        raise PunStartupError, "Failed to start PUN for #{username}: #{stderr.strip}"
      end

      Rails.logger.info("PunManager: nginx_stage started PUN for #{username}")
    end

    # Wait for a user's PUN socket to become available
    #
    # @param username [String] System username
    # @param timeout [Integer] Seconds to wait
    # @raise [PunTimeoutError] if socket doesn't appear in time
    def wait_for_socket(username, timeout)
      path = socket_path(username)
      deadline = Time.now + timeout
      elapsed = 0

      loop do
        if File.exist?(path) && File.socket?(path)
          Rails.logger.info("PunManager: PUN socket ready for #{username} after #{elapsed.round(1)}s")
          return
        end

        if Time.now > deadline
          raise PunTimeoutError, "Timeout waiting for PUN socket after #{timeout}s: #{path}"
        end

        sleep SOCKET_CHECK_INTERVAL
        elapsed += SOCKET_CHECK_INTERVAL
      end
    end

    # Get the configured startup timeout
    #
    # @return [Integer] Timeout in seconds
    def startup_timeout
      ENV.fetch('OOD_PUN_STARTUP_TIMEOUT', DEFAULT_STARTUP_TIMEOUT).to_i
    end

    # Check if impersonation is enabled
    #
    # @return [Boolean] true if impersonation is enabled
    def impersonation_enabled?
      ENV.fetch('OOD_IMPERSONATION_ENABLED', 'true').downcase == 'true'
    end

    # Get the internal API token
    #
    # @return [String, nil] Internal API token or nil if not set
    def internal_api_token
      ENV['OOD_INTERNAL_API_TOKEN']
    end

    private

    def get_startup_lock(username)
      @@locks_mutex.synchronize do
        @@startup_locks[username] ||= Mutex.new
      end
    end
  end
end
