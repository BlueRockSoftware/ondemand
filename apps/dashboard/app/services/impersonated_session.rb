# frozen_string_literal: true

# Value object wrapping session data returned from impersonation responses.
#
# When a session is created via impersonation (through the internal API),
# the response is a JSON hash rather than a BatchConnect::Session object.
# This class provides a compatible interface for the controller.
class ImpersonatedSession
  attr_reader :id, :job_id, :created_at, :user, :session_url

  # @param data [Hash] Parsed JSON response from internal API
  def initialize(data)
    @id = data['id'] || data['session_id']
    @job_id = data['job_id']
    @created_at = data['created_at']
    @user = data['user']
    @session_url = data['session_url']
  end

  # Compatibility with BatchConnect::Session interface
  # @return [String] Session UUID
  def session_id
    @id
  end
end
