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

  test 'get_session prefers OOD_VOLUME_API_TOKEN over the bare name' do
    captured = nil
    env = ENV_VOLUME.merge('OOD_VOLUME_API_TOKEN' => 'ood-token')
    with_modified_env(env) do
      Net::HTTP.any_instance.stubs(:request).with do |req|
        captured = req['Authorization']
        true
      end.returns(http_ok({ id: 'v' }.to_json))
      VolumeApiClient.get_session('v')
    end
    # The PUN scrubs the bare VOLUME_API_TOKEN to nil; the OOD_-prefixed name is
    # what actually survives, so it must win when both are present.
    assert_equal 'Bearer ood-token', captured
  end

  test 'get_session falls back to the bare VOLUME_API_TOKEN when OOD_ is unset' do
    captured = nil
    with_modified_env(ENV_VOLUME) do
      Net::HTTP.any_instance.stubs(:request).with do |req|
        captured = req['Authorization']
        true
      end.returns(http_ok({ id: 'v' }.to_json))
      VolumeApiClient.get_session('v')
    end
    assert_equal 'Bearer vol-token', captured
  end

  test 'mark_consumed PATCHes the user-scoped link endpoint with the container id' do
    req_seen = nil
    env = ENV_VOLUME.merge('OOD_VOLUME_API_TOKEN' => 'ood-token')
    with_modified_env(env) do
      Net::HTTP.any_instance.stubs(:request).with do |req|
        req_seen = req
        true
      end.returns(http_ok({ id: 'vsid-1', state: 'in_use', container_session_id: 'sess-9' }.to_json))
      VolumeApiClient.mark_consumed('chris', 'vol-7', 'vsid-1', 'sess-9')
    end
    assert_kind_of Net::HTTP::Patch, req_seen
    assert_equal '/api/v1/volumes/vol-7/sessions/vsid-1', req_seen.path
    assert_equal 'Bearer ood-token', req_seen['Authorization']
    assert_equal 'chris', req_seen['X-User-ID']
    assert_equal({ 'container_session_id' => 'sess-9' }, JSON.parse(req_seen.body))
  end

  test 'mark_consumed raises VolumeApiError on a non-success response' do
    with_modified_env(ENV_VOLUME) do
      Net::HTTP.any_instance.stubs(:request)
               .returns(http_status(Net::HTTPConflict, '409', 'Conflict'))
      assert_raises(VolumeApiClient::VolumeApiError) do
        VolumeApiClient.mark_consumed('u', 'v', 's', 'c')
      end
    end
  end
end
