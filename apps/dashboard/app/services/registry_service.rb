# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

# Fetches container image tags and digests from a Docker Registry v2 API.
# Caches responses in memory with a configurable TTL to avoid redundant
# network calls. Determines the "current" version as the highest semver tag.
#
# Configuration (environment variables):
#   OOD_REGISTRY_URL       - Registry path (default: 172.20.26.108:5000/deap)
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
    end

    private

    def registry_url
      ENV.fetch("OOD_REGISTRY_URL", DEFAULT_REGISTRY_URL)
    end

    def cache_ttl
      Integer(ENV.fetch("OOD_REGISTRY_CACHE_TTL", DEFAULT_CACHE_TTL))
    end

    # Parse registry_url into API base and repository prefix.
    # "172.20.26.108:5000/deap" => base="http://172.20.26.108:5000", prefix="deap"
    def registry_parts
      url = registry_url
      parts = url.split("/", 2)
      host_port = parts[0]
      prefix = parts[1] || ""
      base = host_port.start_with?("http") ? host_port : "http://#{host_port}"
      [base, prefix]
    end

    def fetch_tags(image_name)
      base, prefix = registry_parts
      repo = prefix.empty? ? image_name : "#{prefix}/#{image_name}"
      uri = URI.parse("#{base}/v2/#{repo}/tags/list")

      response = http_get(uri)
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

      response = http_head(uri, { "Accept" => MANIFEST_ACCEPT })
      return nil unless response.is_a?(Net::HTTPSuccess)

      response["Docker-Content-Digest"]
    rescue StandardError => e
      Rails.logger.warn("RegistryService: fetch_digest failed for #{image_name}:#{tag}: #{e.message}")
      nil
    end

    def http_get(uri)
      Net::HTTP.start(uri.host, uri.port, open_timeout: HTTP_TIMEOUT, read_timeout: HTTP_TIMEOUT) do |http|
        http.get(uri.request_uri)
      end
    end

    def http_head(uri, headers = {})
      req = Net::HTTP::Head.new(uri.request_uri, headers)
      Net::HTTP.start(uri.host, uri.port, open_timeout: HTTP_TIMEOUT, read_timeout: HTTP_TIMEOUT) do |http|
        http.request(req)
      end
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
