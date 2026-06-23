# frozen_string_literal: true

require 'test_helper'

class RegistryServiceTest < ActiveSupport::TestCase
  # base64('robot:secret-pat')
  DOCKERCONFIG = {
    'auths' => { 'ghcr.io' => { 'auth' => 'cm9ib3Q6c2VjcmV0LXBhdA==' } }
  }.to_json.freeze

  ENV_GHCR = {
    'OOD_REGISTRY_API_URL' => 'https://ghcr.io/deap-science',
    'OOD_REGISTRY_DOCKERCONFIG' => DOCKERCONFIG
  }.freeze

  def setup
    RegistryService.clear_cache!
  end

  def teardown
    RegistryService.clear_cache!
  end

  def http_ok(body, headers = {})
    res = Net::HTTPOK.new('1.1', '200', 'OK')
    res.instance_variable_set(:@read, true)
    res.define_singleton_method(:body) { body }
    headers.each { |k, v| res[k] = v }
    res
  end

  def http_unauthorized(www_authenticate)
    res = Net::HTTPUnauthorized.new('1.1', '401', 'Unauthorized')
    res.instance_variable_set(:@read, true)
    res.define_singleton_method(:body) { '' }
    res['WWW-Authenticate'] = www_authenticate
    res
  end

  CHALLENGE = 'Bearer realm="https://ghcr.io/token",service="ghcr.io",' \
              'scope="repository:deap-science/jcvi-jupyter:pull"'

  test 'versions_for performs the ghcr bearer handshake and returns sorted versions' do
    with_modified_env(ENV_GHCR) do
      tags = http_ok({ tags: %w[v1.1.2 latest v1.2.0] }.to_json)
      token = http_ok({ token: 'scoped-token' }.to_json)
      digest = http_ok('', 'Docker-Content-Digest' => 'sha256:abc')

      # The token is cached on first issue, so only the tags call hits the token
      # endpoint; each subsequent digest call is just challenge -> retry.
      # Full sequence: tags 401 -> token -> tags 200,
      # then for each non-latest tag (v1.1.2, then v1.2.0): digest 401 -> digest 200.
      Net::HTTP.any_instance.stubs(:request)
               .returns(http_unauthorized(CHALLENGE)) # tags -> challenge
               .then.returns(token)                    # token issued (cached)
               .then.returns(tags)                     # tags retried OK
               .then.returns(http_unauthorized(CHALLENGE)) # digest #1 -> challenge
               .then.returns(digest)                   # digest #1 retried OK (cached token)
               .then.returns(http_unauthorized(CHALLENGE)) # digest #2 -> challenge
               .then.returns(digest)                   # digest #2 retried OK

      result = RegistryService.versions_for('jcvi-jupyter')

      assert_equal %w[v1.2.0 v1.1.2], result.map { |v| v[:tag] }
      assert result.first[:current], 'highest semver is current'
      assert_equal 'sha256:abc', result.first[:digest]
      refute(result.any? { |v| v[:tag] == 'latest' }, 'latest is excluded')
    end
  end

  test 'parse_bearer_challenge ignores non-Bearer headers' do
    assert_nil RegistryService.send(:parse_bearer_challenge, 'Basic realm="x"')
    assert_nil RegistryService.send(:parse_bearer_challenge, nil)
  end

  test 'registry_basic_auth resolves credentials from the docker config by host' do
    with_modified_env('OOD_REGISTRY_DOCKERCONFIG' => DOCKERCONFIG) do
      assert_equal 'cm9ib3Q6c2VjcmV0LXBhdA==', RegistryService.send(:registry_basic_auth, 'ghcr.io')
      assert_nil RegistryService.send(:registry_basic_auth, 'other.io')
    end
  end

  test 'docker_config tolerates absent or malformed env' do
    with_modified_env('OOD_REGISTRY_DOCKERCONFIG' => nil) do
      assert_equal({}, RegistryService.send(:docker_config))
    end
    RegistryService.clear_cache!
    with_modified_env('OOD_REGISTRY_DOCKERCONFIG' => 'not-json') do
      assert_equal({}, RegistryService.send(:docker_config))
    end
  end

  test 'versions_for returns [] when the registry is unreachable' do
    with_modified_env(ENV_GHCR) do
      Net::HTTP.any_instance.stubs(:request).raises(Errno::ECONNREFUSED)
      assert_equal [], RegistryService.versions_for('jcvi-jupyter')
    end
  end
end
