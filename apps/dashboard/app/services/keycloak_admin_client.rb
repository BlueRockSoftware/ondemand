# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

# Minimal Keycloak Admin REST client: look up a user's immutable `sub`
# (Keycloak user id) by email.
#
# Used by the provisioning endpoint when an admin asks to provision a user
# *by email* and has no `sub` (e.g. creating a session on behalf of a user who
# has never logged in). Authenticates with the `client_credentials` grant of a
# confidential service-account client.
#
# Deployment prerequisite: a confidential client in the realm with its service
# account granted the realm-management `view-users` role. Configure via env:
#   KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_ADMIN_CLIENT_ID,
#   KEYCLOAK_ADMIN_CLIENT_SECRET
# When unset, #configured? is false and the by-email path is unavailable
# (callers must supply a sub instead).
class KeycloakAdminClient
  class Error < StandardError; end
  class NotConfiguredError < Error; end

  OPEN_TIMEOUT = 5
  READ_TIMEOUT = 10

  class << self
    def configured?
      [url, realm, client_id, client_secret].all? { |v| v.to_s.strip != '' }
    end

    # @param email [String]
    # @return [String, nil] the user's Keycloak id (raw sub), or nil if no
    #   exact-match user exists
    # @raise [NotConfiguredError] if Keycloak admin env is not configured
    # @raise [Error] on token/lookup failure
    def lookup_sub_by_email(email)
      raise NotConfiguredError, 'Keycloak admin client is not configured' unless configured?

      users = get_json(
        "/admin/realms/#{realm}/users",
        { 'email' => email, 'exact' => 'true' },
        access_token
      )
      return nil if users.nil? || users.empty?

      # exact=true still returns an array; match email case-insensitively to be safe.
      match = users.find { |u| u['email'].to_s.casecmp?(email.to_s) } || users.first
      id = match['id'].to_s
      id.empty? ? nil : id
    end

    private

    def url
      ENV['KEYCLOAK_URL']
    end

    def realm
      ENV['KEYCLOAK_REALM']
    end

    def client_id
      ENV['KEYCLOAK_ADMIN_CLIENT_ID']
    end

    def client_secret
      ENV['KEYCLOAK_ADMIN_CLIENT_SECRET']
    end

    def access_token
      res = post_form(
        "/realms/#{realm}/protocol/openid-connect/token",
        'grant_type' => 'client_credentials',
        'client_id' => client_id,
        'client_secret' => client_secret
      )
      token = res['access_token'].to_s
      raise Error, 'Keycloak token response had no access_token' if token.empty?

      token
    end

    def post_form(path, form)
      uri = URI.join(url.to_s.chomp('/') + '/', path.sub(%r{\A/}, ''))
      req = Net::HTTP::Post.new(uri)
      req.set_form_data(form)
      parse_json(perform(uri, req), 'token request')
    end

    def get_json(path, query, token)
      uri = URI.join(url.to_s.chomp('/') + '/', path.sub(%r{\A/}, ''))
      uri.query = URI.encode_www_form(query)
      req = Net::HTTP::Get.new(uri)
      req['Authorization'] = "Bearer #{token}"
      req['Accept'] = 'application/json'
      parse_json(perform(uri, req), 'user lookup')
    end

    def perform(uri, req)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = OPEN_TIMEOUT
      http.read_timeout = READ_TIMEOUT
      res = http.request(req)
      unless res.is_a?(Net::HTTPSuccess)
        raise Error, "Keycloak request to #{uri.path} failed: #{res.code}"
      end

      res.body
    rescue Error
      raise
    rescue StandardError => e
      raise Error, "Keycloak request to #{uri.path} failed: #{e.message}"
    end

    def parse_json(body, context)
      JSON.parse(body)
    rescue JSON::ParserError => e
      raise Error, "Keycloak #{context} returned invalid JSON: #{e.message}"
    end
  end
end
