# frozen_string_literal: true

require 'socket'
require 'uri'
require 'json'
require 'timeout'

# HTTP client for communicating via Unix sockets
# Used for internal PUN-to-PUN communication during user impersonation
class UnixSocketHttp
  # Default timeout for socket operations
  DEFAULT_TIMEOUT = 30

  # Custom errors for socket communication
  class SocketError < StandardError; end
  class ConnectionError < SocketError; end
  class TimeoutError < SocketError; end
  class ResponseError < SocketError; end

  # HTTP Response wrapper
  class Response
    attr_reader :code, :message, :headers, :body

    def initialize(code:, message:, headers:, body:)
      @code = code.to_i
      @message = message
      @headers = headers
      @body = body
    end

    def success?
      code >= 200 && code < 300
    end

    def json
      @json ||= JSON.parse(body)
    rescue JSON::ParserError
      nil
    end
  end

  attr_reader :socket_path, :timeout

  def initialize(socket_path, timeout: DEFAULT_TIMEOUT)
    @socket_path = socket_path
    @timeout = timeout
  end

  # Perform a POST request via Unix socket
  #
  # @param path [String] Request path (e.g., '/internal/batch_connect/sessions')
  # @param body [Hash, String] Request body (will be JSON encoded if Hash)
  # @param headers [Hash] Additional headers
  # @return [Response] HTTP response
  def post(path, body, headers = {})
    body_str = body.is_a?(Hash) ? body.to_json : body.to_s
    request(
      method: 'POST',
      path: path,
      body: body_str,
      headers: default_headers.merge(headers).merge('Content-Length' => body_str.bytesize.to_s)
    )
  end

  # Perform a GET request via Unix socket
  #
  # @param path [String] Request path
  # @param headers [Hash] Additional headers
  # @return [Response] HTTP response
  def get(path, headers = {})
    request(
      method: 'GET',
      path: path,
      body: nil,
      headers: default_headers.merge(headers)
    )
  end

  # Perform a DELETE request via Unix socket
  #
  # @param path [String] Request path
  # @param headers [Hash] Additional headers
  # @return [Response] HTTP response
  def delete(path, headers = {})
    request(
      method: 'DELETE',
      path: path,
      body: nil,
      headers: default_headers.merge(headers)
    )
  end

  private

  def default_headers
    {
      'Host' => 'localhost',
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Connection' => 'close'
    }
  end

  def request(method:, path:, body:, headers:)
    socket = nil

    Timeout.timeout(timeout) do
      socket = connect_socket
      send_request(socket, method, path, headers, body)
      read_response(socket)
    end
  rescue Timeout::Error
    raise TimeoutError, "Request to #{socket_path} timed out after #{timeout}s"
  rescue Errno::ENOENT
    raise ConnectionError, "Socket not found: #{socket_path}"
  rescue Errno::ECONNREFUSED
    raise ConnectionError, "Connection refused: #{socket_path}"
  rescue Errno::EPERM, Errno::EACCES
    raise ConnectionError, "Permission denied: #{socket_path}"
  ensure
    socket&.close
  end

  def connect_socket
    unless File.exist?(socket_path)
      raise ConnectionError, "Socket does not exist: #{socket_path}"
    end

    unless File.socket?(socket_path)
      raise ConnectionError, "Path is not a socket: #{socket_path}"
    end

    UNIXSocket.new(socket_path)
  end

  def send_request(socket, method, path, headers, body)
    # Build HTTP request
    request_line = "#{method} #{path} HTTP/1.1\r\n"
    header_lines = headers.map { |k, v| "#{k}: #{v}\r\n" }.join
    
    request = "#{request_line}#{header_lines}\r\n"
    request += body if body

    socket.write(request)
  end

  def read_response(socket)
    # Read status line
    status_line = socket.gets
    unless status_line
      raise ResponseError, "Empty response from socket"
    end

    match = status_line.match(%r{HTTP/[\d.]+\s+(\d+)\s+(.*)})
    unless match
      raise ResponseError, "Invalid HTTP response: #{status_line}"
    end

    code = match[1]
    message = match[2].strip

    # Read headers
    headers = {}
    while (line = socket.gets) && line != "\r\n"
      key, value = line.split(':', 2)
      headers[key.strip.downcase] = value.strip if key && value
    end

    # Read body
    body = read_body(socket, headers)

    Response.new(code: code, message: message, headers: headers, body: body)
  end

  def read_body(socket, headers)
    content_length = headers['content-length']&.to_i
    transfer_encoding = headers['transfer-encoding']

    if transfer_encoding&.include?('chunked')
      read_chunked_body(socket)
    elsif content_length && content_length > 0
      socket.read(content_length)
    else
      # Read until connection closes
      socket.read
    end
  end

  def read_chunked_body(socket)
    body = String.new

    loop do
      chunk_size_line = socket.gets
      break unless chunk_size_line

      chunk_size = chunk_size_line.strip.to_i(16)
      break if chunk_size == 0

      body += socket.read(chunk_size)
      socket.gets # Read trailing CRLF
    end

    body
  end
end
