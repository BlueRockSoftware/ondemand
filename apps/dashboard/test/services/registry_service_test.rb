# frozen_string_literal: true

require 'test_helper'

class RegistryServiceTest < ActiveSupport::TestCase
  # docker config json as it appears in the ghcr-pull secret's .dockerconfigjson
  DOCKERCONFIG = {
    auths: { 'ghcr.io' => { auth: Base64.strict_encode64('deap:ghp_secret') } }
  }.to_json.freeze

  GHCR_ENV = {
    'OOD_REGISTRY_URL' => 'https://ghcr.io/deap-science',
    'OOD_REGISTRY_DOCKERCONFIG' => DOCKERCONFIG,
    'OOD_REGISTRY_USERNAME' => nil,
    'OOD_REGISTRY_PASSWORD' => nil
  }.freeze

  def setup
    RegistryService.clear_cache!
  end

  def teardown
    RegistryService.clear_cache!
  end

  def response(klass, code, msg, body: '', headers: {})
    res = klass.new('1.1', code, msg)
    res.instance_variable_set(:@read, true)
    res.define_singleton_method(:body) { body }
    headers.each { |k, v| res[k] = v }
    res
  end

  def challenge
    response(Net::HTTPUnauthorized, '401', 'Unauthorized', headers: {
               'WWW-Authenticate' =>
                 'Bearer realm="https://ghcr.io/token",service="ghcr.io",' \
                 'scope="repository:deap-science/jcvi-x:pull"'
             })
  end

  test 'ghcr 401 challenge triggers a token handshake with pull-secret creds, then returns versions' do
    token_resp = response(Net::HTTPOK, '200', 'OK', body: { token: 'bearer-xyz' }.to_json)
    tags_resp  = response(Net::HTTPOK, '200', 'OK', body: { tags: %w[v1.0.0 v1.2.0 latest] }.to_json)
    manifest_resp = response(Net::HTTPOK, '200', 'OK', headers: { 'Docker-Content-Digest' => 'sha256:abc' })

    with_modified_env(GHCR_ENV) do
      # Define general (unauthenticated) matchers first, then the specific
      # Bearer/Basic ones so mocha's most-recent-wins picks the right branch.
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/tags/list') }.returns(challenge)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/manifests/') }.returns(challenge)
      # Token endpoint must be reached WITH Basic auth derived from the docker config.
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.start_with?('/token') && req['Authorization'] == "Basic #{Base64.strict_encode64('deap:ghp_secret')}" }
               .returns(token_resp)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/tags/list') && req['Authorization'] == 'Bearer bearer-xyz' }
               .returns(tags_resp)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/manifests/') && req['Authorization'] == 'Bearer bearer-xyz' }
               .returns(manifest_resp)

      versions = RegistryService.versions_for('jcvi-x')

      tags = versions.map { |v| v[:tag] }
      assert_equal %w[v1.2.0 v1.0.0], tags, 'drops :latest and sorts semver descending'
      assert_equal 'sha256:abc', versions.first[:digest]
      assert versions.first[:current], 'highest semver is marked current'
      refute versions.last[:current]
    end
  end

  test 'anonymous plain-HTTP registry returns versions without an auth handshake' do
    tags_resp = response(Net::HTTPOK, '200', 'OK', body: { tags: %w[v2.0.0] }.to_json)
    manifest_resp = response(Net::HTTPOK, '200', 'OK', headers: { 'Docker-Content-Digest' => 'sha256:def' })

    with_modified_env('OOD_REGISTRY_URL' => 'http://registry.svc:5000/deap',
                      'OOD_REGISTRY_DOCKERCONFIG' => nil) do
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/tags/list') }.returns(tags_resp)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/manifests/') }.returns(manifest_resp)

      versions = RegistryService.versions_for('jcvi-x')

      assert_equal %w[v2.0.0], versions.map { |v| v[:tag] }
      assert_equal 'sha256:def', versions.first[:digest]
    end
  end

  test 'returns an empty array (never raises) when the registry is unreachable' do
    with_modified_env(GHCR_ENV) do
      Net::HTTP.any_instance.stubs(:request).raises(Errno::ECONNREFUSED)

      assert_equal [], RegistryService.versions_for('jcvi-x')
    end
  end

  test 'serves a stale cached value when a later refresh fails' do
    tags_resp = response(Net::HTTPOK, '200', 'OK', body: { tags: %w[v1.0.0] }.to_json)
    manifest_resp = response(Net::HTTPOK, '200', 'OK', headers: { 'Docker-Content-Digest' => 'sha256:abc' })

    with_modified_env(GHCR_ENV.merge('OOD_REGISTRY_CACHE_TTL' => '0')) do
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/tags/list') && req['Authorization'] }.returns(tags_resp)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/tags/list') }.returns(challenge)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/manifests/') && req['Authorization'] }.returns(manifest_resp)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.include?('/manifests/') }.returns(challenge)
      Net::HTTP.any_instance.stubs(:request)
               .with { |req| req.path.start_with?('/token') }
               .returns(response(Net::HTTPOK, '200', 'OK', body: { token: 't' }.to_json))

      first = RegistryService.versions_for('jcvi-x')
      assert_equal %w[v1.0.0], first.map { |v| v[:tag] }

      # Now the registry breaks; with TTL 0 the cache entry is expired, but the
      # ignore-expiry fallback should still surface the last good result.
      Net::HTTP.any_instance.stubs(:request).raises(Errno::ECONNREFUSED)
      stale = RegistryService.versions_for('jcvi-x')
      assert_equal %w[v1.0.0], stale.map { |v| v[:tag] }
    end
  end
end
