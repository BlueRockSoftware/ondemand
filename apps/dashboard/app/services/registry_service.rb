# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'base64'

# Fetches container image tags and digests from a Docker Registry v2 API.
# Caches responses in memory with a configurable TTL to avoid redundant
# network calls. Determines the "current" version as the highest semver tag.
#
# Supports both anonymous plain-HTTP registries (e.g. an in-cluster Joxit
# registry) and token-authenticated HTTPS registries such as GitHub Container
# Registry (ghcr.io). For the latter, a 401 challenge triggers a Bearer-token
# handshake against the registry's auth realm using credentials pulled from the
# deployment's existing image-pull secret.
#
# Configuration (environment variables):
#   OOD_REGISTRY_URL          - Registry path. Scheme optional; a bare host
#                               defaults to HTTPS. (default: the in-cluster
#                               plain-HTTP registry below)
#   OOD_REGISTRY_CACHE_TTL    - Cache TTL in seconds (default: 300)
#   OOD_REGISTRY_DOCKERCONFIG - A docker config JSON (the `.dockerconfigjson`
#                               value of the ghcr-pull secret). Parsed to find
#                               credentials for the registry host.
#   OOD_REGISTRY_USERNAME     - Optional explicit username (overrides the
#   OOD_REGISTRY_PASSWORD       docker config when both are set).
#
# Usage:
#   versions = RegistryService.versions_for("jcvi-rstudio-base")
#   # => [{ tag: "v1.0.83", digest: "sha256:...", current: true }, ...]
#
class RegistryService
  HTTP_TIMEOUT = 5
  DEFAULT_REGISTRY_URL = "http://172.20.26.108:5000/deap"
  DEFAULT_CACHE_TTL = 300
  MANIFEST_ACCEPT = "application/vnd.docker.distribution.manifest.v2+json"

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

    # Clear the in-memory cache (useful for testing).
    def clear_cache!
      @cache = {}
      @token_cache = {}
    end

    private

    def registry_url
      ENV.fetch("OOD_REGISTRY_URL", DEFAULT_REGISTRY_URL)
    end

    def cache_ttl
      Integer(ENV.fetch("OOD_REGISTRY_CACHE_TTL", DEFAULT_CACHE_TTL))
    end

    # Parse registry_url into API base and repository prefix.
    # "ghcr.io/deap-science"          => base="https://ghcr.io",            prefix="deap-science"
    # "http://172.20.26.108:5000/deap" => base="http://172.20.26.108:5000", prefix="deap"
    #
    # A bare host (no scheme) defaults to HTTPS — the secure default. Plain-HTTP
    # registries must be configured with an explicit "http://" scheme.
    def registry_parts
      url = registry_url
      scheme_match = url.match(%r{\A(https?)://(.+)\z})
      scheme = scheme_match ? scheme_match[1] : "https"
      remainder = scheme_match ? scheme_match[2] : url

      parts = remainder.split("/", 2)
      host_port = parts[0]
      prefix = parts[1] || ""
      ["#{scheme}://#{host_port}", prefix]
    end

    def fetch_tags(image_name)
      base, prefix = registry_parts
      repo = prefix.empty? ? image_name : "#{prefix}/#{image_name}"
      uri = URI.parse("#{base}/v2/#{repo}/tags/list")

      response = authed_request(uri, repo)
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

      response = authed_request(uri, repo, method: :head, headers: { "Accept" => MANIFEST_ACCEPT })
      return nil unless response.is_a?(Net::HTTPSuccess)

      response["Docker-Content-Digest"]
    rescue StandardError => e
      Rails.logger.warn("RegistryService: fetch_digest failed for #{image_name}:#{tag}: #{e.message}")
      nil
    end

    # Perform a registry request, transparently handling a Bearer-token
    # challenge: on a 401 carrying a WWW-Authenticate header, obtain a token
    # from the named realm and retry once with it. `repo` is the fully-prefixed
    # repository (e.g. "deap-science/jcvi-rstudio-base"), used to scope the
    # token and cache it.
    def authed_request(uri, repo, method: :get, headers: {})
      response = raw_request(uri, method, headers)
      return response unless response.is_a?(Net::HTTPUnauthorized)

      challenge = parse_www_authenticate(response["WWW-Authenticate"])
      return response unless challenge && challenge[:realm]

      token = bearer_token(uri.host, repo, challenge)
      return response unless token

      raw_request(uri, method, headers.merge("Authorization" => "Bearer #{token}"))
    end

    def raw_request(uri, method, headers)
      request = (method == :head ? Net::HTTP::Head : Net::HTTP::Get).new(uri.request_uri)
      headers.each { |k, v| request[k] = v }

      start_http(uri) { |http| http.request(request) }
    end

    def start_http(uri)
      Net::HTTP.start(
        uri.host, uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: HTTP_TIMEOUT,
        read_timeout: HTTP_TIMEOUT
      ) { |http| yield(http) }
    end

    # Obtain (and cache) a Bearer token for `repo` from the challenge realm.
    def bearer_token(registry_host, repo, challenge)
      cache_key = "registry_token:#{challenge[:realm]}:#{challenge[:scope] || repo}"
      cached = read_cache(cache_key)
      return cached if cached

      realm = URI.parse(challenge[:realm])
      query = {}
      query["service"] = challenge[:service] if challenge[:service]
      query["scope"]   = challenge[:scope] || "repository:#{repo}:pull"
      realm.query = URI.encode_www_form(query)

      request = Net::HTTP::Get.new(realm.request_uri)
      creds = registry_credentials(registry_host)
      request.basic_auth(creds[0], creds[1]) if creds

      response = start_http(realm) { |http| http.request(request) }
      return nil unless response.is_a?(Net::HTTPSuccess)

      body = JSON.parse(response.body)
      token = body["token"] || body["access_token"]
      # Tokens are short-lived; cache for a minute, well under their lifetime.
      write_cache(cache_key, token, ttl: 60) if token
      token
    rescue StandardError => e
      Rails.logger.warn("RegistryService: token fetch failed for #{repo}: #{e.message}")
      nil
    end

    # Parse a "Bearer realm=...,service=...,scope=..." challenge into a hash.
    def parse_www_authenticate(header)
      return nil unless header && header.start_with?("Bearer ")

      params = {}
      header.sub(/\ABearer\s+/, "").scan(/(\w+)="([^"]*)"/) do |key, value|
        params[key.to_sym] = value
      end
      params
    end

    # Resolve registry credentials. Explicit env vars win; otherwise parse the
    # docker config JSON (the image-pull secret) for an entry matching the host.
    def registry_credentials(host)
      user = ENV["OOD_REGISTRY_USERNAME"].to_s
      pass = ENV["OOD_REGISTRY_PASSWORD"].to_s
      return [user, pass] unless user.empty? || pass.empty?

      config = docker_config
      return nil unless config

      auths = config["auths"] || {}
      entry = auths[host] || auths["https://#{host}"] || auths["#{host}/"]
      return nil unless entry

      if entry["auth"].to_s != ""
        decoded = Base64.decode64(entry["auth"].to_s)
        u, sep, p = decoded.partition(":")
        return [u, p] if sep == ":" && !u.empty?
      end
      return [entry["username"], entry["password"]] if entry["username"] && entry["password"]

      nil
    end

    def docker_config
      raw = ENV["OOD_REGISTRY_DOCKERCONFIG"].to_s
      return nil if raw.empty?

      JSON.parse(raw)
    rescue StandardError => e
      Rails.logger.warn("RegistryService: could not parse OOD_REGISTRY_DOCKERCONFIG: #{e.message}")
      nil
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

    def write_cache(key, data, ttl: nil)
      cache_store[key] = {
        data: data,
        expires_at: Time.now + (ttl || cache_ttl)
      }
    end
  end
end
