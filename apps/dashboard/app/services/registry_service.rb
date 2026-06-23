# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

# Fetches container image tags and digests from a Docker Registry v2 API.
# Caches responses in memory with a configurable TTL to avoid redundant
# network calls. Determines the "current" version as the highest semver tag.
#
# Configuration (environment variables):
#   OOD_REGISTRY_API_URL   - Docker v2 API endpoint, with scheme
#                            (e.g. https://ghcr.io/deap-science). Falls back to
#                            OOD_REGISTRY_URL, then DEFAULT_REGISTRY_URL.
#   OOD_REGISTRY_URL       - Bare registry path for image refs (no scheme);
#                            used here only as a backward-compat fallback.
#   OOD_REGISTRY_DOCKERCONFIG - Docker config JSON (the image-pull secret's
#                            .dockerconfigjson). Parsed for per-host credentials
#                            to perform the registry's Bearer-token handshake
#                            (required by ghcr.io). Optional: plain-HTTP/anonymous
#                            registries need no token and ignore this.
#   OOD_REGISTRY_CACHE_TTL - Cache TTL in seconds (default: 300)
#
# Usage:
#   versions = RegistryService.versions_for("jcvi-rstudio-base")
#   # => [{ tag: "v1.0.83", digest: "sha256:...", current: true }, ...]
#
class RegistryService
  HTTP_TIMEOUT = 5
  DEFAULT_REGISTRY_URL = "172.20.26.108:5000/deap"
  DEFAULT_CACHE_TTL = 300
  # Token lifetime is conservative: ghcr issues ~5-minute tokens, so reuse the
  # one token across a single image's tag + per-tag digest calls.
  TOKEN_TTL = 240
  # Accept the full manifest/index set so multi-arch images (an OCI image index
  # on ghcr) resolve to their top-level digest, matching what a pull would use.
  MANIFEST_ACCEPT = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json"
  ].join(", ")

  class << self
    # Fetch versions (tags + digests) for a container image.
    #
    # @param image_name [String] Image name without registry prefix (e.g. "jcvi-rstudio-base")
    # @return [Array<Hash>] Sorted versions with :tag, :digest, :current keys
    def versions_for(image_name)
      cache_key = "registry_versions:#{registry_url}:#{image_name}"
      cached = read_cache(cache_key)
      return cached if cached

      tags = fetch_tags(image_name)
      return [] if tags.empty?

      versions = tags.filter_map do |tag|
        next if tag == "latest"

        digest = fetch_digest(image_name, tag)
        { tag: tag, digest: digest || "", current: false }
      end

      mark_current!(versions)
      write_cache(cache_key, versions)
      versions
    rescue StandardError => e
      Rails.logger.warn("RegistryService: failed to fetch versions for #{image_name}: #{e.message}")
      cached_fallback = read_cache(cache_key, ignore_expiry: true)
      return cached_fallback if cached_fallback

      []
    end

    # Return the current (highest semver) tag for an image.
    #
    # @param image_name [String] Image name without registry prefix
    # @return [String, nil] The current tag or nil if none found
    def current_tag(image_name)
      versions = versions_for(image_name)
      current = versions.find { |v| v[:current] }
      current&.dig(:tag)
    end

    # Clear the in-memory caches (useful for testing).
    def clear_cache!
      @cache = {}
      @token_cache = {}
      @docker_config = nil
    end

    private

    # API base for Docker v2 calls. Prefers OOD_REGISTRY_API_URL (carries an
    # explicit scheme so ghcr.io is reached over HTTPS). OOD_REGISTRY_URL is the
    # bare host[:port]/prefix the session submit templates interpolate into
    # Kubernetes image references, where a scheme is invalid; it is only a
    # backward-compat fallback here.
    def registry_url
      ENV["OOD_REGISTRY_API_URL"] || ENV.fetch("OOD_REGISTRY_URL", DEFAULT_REGISTRY_URL)
    end

    def cache_ttl
      Integer(ENV.fetch("OOD_REGISTRY_CACHE_TTL", DEFAULT_CACHE_TTL))
    end

    # Parse registry_url into API base and repository prefix. A bare value (no
    # scheme) defaults to plain HTTP, matching the in-cluster registry; an
    # explicit scheme is honored (ghcr.io needs HTTPS).
    #   "https://ghcr.io/deap-science" => base="https://ghcr.io",          prefix="deap-science"
    #   "172.20.26.108:5000/deap"      => base="http://172.20.26.108:5000", prefix="deap"
    def registry_parts
      url = registry_url
      url = "http://#{url}" unless url.match?(%r{\Ahttps?://})
      uri = URI.parse(url)

      base = "#{uri.scheme}://#{uri.host}"
      base += ":#{uri.port}" if uri.port && uri.port != uri.default_port
      prefix = uri.path.sub(%r{\A/+}, "")
      [base, prefix]
    end

    def fetch_tags(image_name)
      base, prefix = registry_parts
      repo = prefix.empty? ? image_name : "#{prefix}/#{image_name}"
      uri = URI.parse("#{base}/v2/#{repo}/tags/list")

      response = authorized_request(:get, uri)
      return [] unless response.is_a?(Net::HTTPSuccess)

      data = JSON.parse(response.body)
      data["tags"] || []
    rescue StandardError => e
      Rails.logger.warn("RegistryService: fetch_tags failed for #{image_name}: #{e.message}")
      []
    end

    def fetch_digest(image_name, tag)
      base, prefix = registry_parts
      repo = prefix.empty? ? image_name : "#{prefix}/#{image_name}"
      uri = URI.parse("#{base}/v2/#{repo}/manifests/#{tag}")

      response = authorized_request(:head, uri, { "Accept" => MANIFEST_ACCEPT })
      return nil unless response.is_a?(Net::HTTPSuccess)

      response["Docker-Content-Digest"]
    rescue StandardError => e
      Rails.logger.warn("RegistryService: fetch_digest failed for #{image_name}:#{tag}: #{e.message}")
      nil
    end

    # Perform a registry request, transparently satisfying a Docker Registry v2
    # Bearer-token challenge (ghcr.io) by fetching a token and retrying once.
    # Plain/anonymous registries return success on the first try and are untouched.
    def authorized_request(method, uri, headers = {})
      response = http_request(method, uri, headers)
      return response unless response.is_a?(Net::HTTPUnauthorized)

      challenge = parse_bearer_challenge(response["WWW-Authenticate"])
      return response unless challenge

      token = bearer_token(challenge, uri.host)
      return response unless token

      http_request(method, uri, headers.merge("Authorization" => "Bearer #{token}"))
    end

    def http_request(method, uri, headers = {})
      request_class = method == :head ? Net::HTTP::Head : Net::HTTP::Get
      request = request_class.new(uri.request_uri, headers)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.is_a?(URI::HTTPS),
                      open_timeout: HTTP_TIMEOUT, read_timeout: HTTP_TIMEOUT) do |http|
        http.request(request)
      end
    end

    # Parse a `WWW-Authenticate: Bearer realm="...",service="...",scope="..."`
    # header into a params hash, or nil if it is not a Bearer challenge.
    def parse_bearer_challenge(header)
      return nil unless header.to_s.start_with?("Bearer ")

      params = header.sub(/\ABearer\s+/, "").scan(/(\w+)="([^"]*)"/).to_h
      params["realm"] ? params : nil
    end

    # Exchange a Bearer challenge for an access token, authenticating to the
    # token endpoint with the registry host's docker-config credentials when
    # available. Tokens are cached per scope for their (short) lifetime so a
    # single versions_for refresh reuses one token across all its requests.
    def bearer_token(challenge, registry_host)
      scope = challenge["scope"].to_s
      cached = token_cache[scope]
      return cached[:token] if cached && cached[:expires_at] > Time.now

      realm = URI.parse(challenge["realm"])
      query = { "service" => challenge["service"], "scope" => challenge["scope"] }.compact
      realm.query = URI.encode_www_form(query) unless query.empty?

      headers = {}
      basic = registry_basic_auth(registry_host)
      headers["Authorization"] = "Basic #{basic}" if basic

      response = http_request(:get, realm, headers)
      return nil unless response.is_a?(Net::HTTPSuccess)

      token = JSON.parse(response.body).values_at("token", "access_token").compact.first
      token_cache[scope] = { token: token, expires_at: Time.now + TOKEN_TTL } if token
      token
    rescue StandardError => e
      Rails.logger.warn("RegistryService: token handshake failed for #{registry_host}: #{e.message}")
      nil
    end

    # Base64 `user:password` for a registry host from the docker config, or nil.
    # The docker config's `auth` field is already base64(user:password), which is
    # exactly the credential the token endpoint expects for HTTP Basic auth.
    def registry_basic_auth(host)
      auths = docker_config["auths"] || {}
      entry = auths[host] || auths["https://#{host}"] || auths["http://#{host}"]
      entry && entry["auth"]
    end

    def docker_config
      raw = ENV["OOD_REGISTRY_DOCKERCONFIG"]
      return {} if raw.nil? || raw.empty?

      @docker_config ||= JSON.parse(raw)
    rescue JSON::ParserError => e
      Rails.logger.warn("RegistryService: invalid OOD_REGISTRY_DOCKERCONFIG: #{e.message}")
      {}
    end

    def token_cache
      @token_cache ||= {}
    end

    # Sort versions by semver descending; mark highest as current.
    def mark_current!(versions)
      semver, non_semver = versions.partition { |v| semver?(v[:tag]) }

      semver.sort_by! { |v| gem_version(v[:tag]) }.reverse!
      non_semver.sort_by! { |v| v[:tag] }.reverse!

      sorted = semver + non_semver
      versions.replace(sorted)

      target = semver.first || non_semver.first
      target[:current] = true if target
    end

    def semver?(tag)
      gem_version(tag)
      true
    rescue ArgumentError
      false
    end

    def gem_version(tag)
      normalized = tag.sub(/\Av/, "")
      Gem::Version.new(normalized)
    end

    # In-memory cache with TTL.
    def cache_store
      @cache ||= {}
    end

    def read_cache(key, ignore_expiry: false)
      entry = cache_store[key]
      return nil unless entry

      if ignore_expiry || entry[:expires_at] > Time.now
        entry[:data]
      end
    end

    def write_cache(key, data)
      cache_store[key] = {
        data: data,
        expires_at: Time.now + cache_ttl
      }
    end
  end
end
