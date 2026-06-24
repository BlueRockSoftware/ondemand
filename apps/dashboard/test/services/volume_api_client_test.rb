# frozen_string_literal: true

require 'test_helper'

# Unit tests for the read-only Volume API client used to validate codespace
# mount handles before launch (spec 049, FR-006).
class VolumeApiClientTest < ActiveSupport::TestCase
  ENV_VOLUME = {
    'VOLUME_API_URL' => 'https://volume-api.test',
    'VOLUME_API_TOKEN' => 'vol-token'
  }.freeze

  def http_ok(body)
    res = Net::HTTPOK.new('1.1', '200', 'OK')
    res.instance_variable_set(:@read, true)
    res.define_singleton_method(:body) { body }
    res
  end

  def http_status(klass, code, msg, body = '')
    res = klass.new('1.1', code, msg)
    res.instance_variable_set(:@read, true)
    res.define_singleton_method(:body) { body }
    res
  end

  test 'get_session parses a 200 session body into a hash' do
    with_modified_env(ENV_VOLUME) do
      Net::HTTP.any_instance.stubs(:request).returns(
        http_ok({ id: 'vsid-1', user_id: 'u', mount_path: 'p',
                  state: 'ready', container_session_id: nil }.to_json)
      )
      session = VolumeApiClient.get_session('vsid-1')
      assert_equal 'vsid-1', session['id']
      assert_equal 'ready', session['state']
      assert_nil session['container_session_id']
    end
  end

  test 'get_session returns nil on 404' do
    with_modified_env(ENV_VOLUME) do
      Net::HTTP.any_instance.stubs(:request)
               .returns(http_status(Net::HTTPNotFound, '404', 'Not Found', '{"detail":"nope"}'))
      assert_nil VolumeApiClient.get_session('missing')
    end
  end

  test 'get_session raises VolumeApiError on a non-200/404 response' do
    with_modified_env(ENV_VOLUME) do
      Net::HTTP.any_instance.stubs(:request)
               .returns(http_status(Net::HTTPInternalServerError, '500', 'Error'))
      assert_raises(VolumeApiClient::VolumeApiError) { VolumeApiClient.get_session('x') }
    end
  end

  test 'get_session raises VolumeApiError on a transport failure' do
    with_modified_env(ENV_VOLUME) do
      Net::HTTP.any_instance.stubs(:request).raises(Errno::ECONNREFUSED)
      assert_raises(VolumeApiClient::VolumeApiError) { VolumeApiClient.get_session('x') }
    end
  end

  test 'get_session raises VolumeApiError when VOLUME_API_URL is unconfigured' do
    with_modified_env('VOLUME_API_URL' => nil) do
      assert_raises(VolumeApiClient::VolumeApiError) { VolumeApiClient.get_session('x') }
    end
  end
end
