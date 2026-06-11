# frozen_string_literal: true

require 'test_helper'

# Cross-user session actions (show/connect/destroy) must never evaluate a
# session's job state outside the owner's PUN: the k8s adapter namespaces
# kubectl by the calling PUN user, and ood_core reports a pod it cannot see
# as "completed". These tests pin the owner-resolution and routing behavior.
class Api::V1::BatchConnect::SessionsControllerTest < ActionDispatch::IntegrationTest
  ADMIN_TOKEN = 'ood-api-admin-test'
  ADMIN_USER = 'ood_api_admin'
  OWNER = 'chris_zevross_8949'
  SESSION_ID = '2a18060a-efc5-44e9-98d3-965100d6e5d8'

  def auth_headers
    { 'Authorization' => "Bearer #{ADMIN_TOKEN}" }
  end

  def controller_stubs
    Api::V1::BatchConnect::SessionsController.any_instance
  end

  def enable_impersonation
    PunManager.stubs(:impersonation_enabled?).returns(true)
    PunManager.stubs(:internal_api_token).returns('internal-token')
  end

  def disable_impersonation
    PunManager.stubs(:impersonation_enabled?).returns(false)
  end

  def stub_session_lookup(user: OWNER, session: stub_everything('session'))
    controller_stubs.stubs(:find_session_by_id).returns({ user: user, session: session })
  end

  setup do
    controller_stubs.stubs(:get_current_pun_user).returns(ADMIN_USER)
  end

  # --- connect ---

  test 'connect without user resolves the owner and forwards via impersonation' do
    enable_impersonation
    stub_session_lookup

    ImpersonationService.expects(:get_session)
                        .with(SESSION_ID, OWNER, request_host: anything)
                        .returns({
                                   'session' => { 'status' => 'running' },
                                   'connection' => { 'host' => '10.0.0.1', 'port' => 8080 },
                                   'connection_url' => '/node/10.0.0.1/8080/'
                                 })

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}/connect", headers: auth_headers

    assert_response :success
    body = JSON.parse(response.body)
    assert_equal 'success', body['status']
    assert_equal OWNER, body['user']
    assert_equal '/node/10.0.0.1/8080/', body['connection_url']
  end

  test 'connect without user returns 503 instead of fake completed when impersonation is unavailable' do
    disable_impersonation
    stub_session_lookup

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}/connect", headers: auth_headers

    assert_response :service_unavailable
    body = JSON.parse(response.body)
    assert_equal 'IMPERSONATION_UNAVAILABLE', body['code']
    assert_equal OWNER, body['user']
    refute_match(/completed/, body['message'])
  end

  test 'connect returns 404 when the session does not exist' do
    enable_impersonation
    controller_stubs.stubs(:find_session_by_id).returns(nil)

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}/connect", headers: auth_headers

    assert_response :not_found
  end

  test 'connect with explicit user forwards via impersonation without local lookup' do
    enable_impersonation
    controller_stubs.expects(:find_session_by_id).never

    ImpersonationService.expects(:get_session)
                        .with(SESSION_ID, OWNER, request_host: anything)
                        .returns({ 'session' => { 'status' => 'running' }, 'connection' => {}, 'connection_url' => nil })

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}/connect",
        params: { user: OWNER }, headers: auth_headers

    assert_response :success
  end

  test 'connect evaluates locally when the current PUN user owns the session' do
    enable_impersonation
    session = mock('session')
    session.stubs(:running?).returns(true)
    session.stubs(:completed?).returns(false)
    session.stubs(:id).returns(SESSION_ID)
    session.stubs(:connect).returns(stub(to_h: { host: '10.0.0.2', port: 8080 }))
    stub_session_lookup(user: ADMIN_USER, session: session)

    ImpersonationService.expects(:get_session).never

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}/connect", headers: auth_headers

    assert_response :success
    body = JSON.parse(response.body)
    assert_equal 'running', body['session_status']
    assert_equal '/node/10.0.0.2/8080/', body['connection_url']
  end

  # --- show ---

  test 'show without user resolves the owner and forwards via impersonation' do
    enable_impersonation
    stub_session_lookup

    ImpersonationService.expects(:get_session)
                        .with(SESSION_ID, OWNER, request_host: anything)
                        .returns({
                                   'session' => { 'id' => SESSION_ID, 'status' => 'running' },
                                   'connection_url' => '/node/10.0.0.1/8080/'
                                 })

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}", headers: auth_headers

    assert_response :success
    body = JSON.parse(response.body)
    assert_equal 'running', body.dig('session', 'status')
  end

  test 'show without user returns 503 when impersonation is unavailable' do
    disable_impersonation
    stub_session_lookup

    get "/api/v1/batch_connect/sessions/#{SESSION_ID}", headers: auth_headers

    assert_response :service_unavailable
    assert_equal 'IMPERSONATION_UNAVAILABLE', JSON.parse(response.body)['code']
  end

  # --- destroy ---

  test 'destroy without user resolves the owner and forwards via impersonation' do
    enable_impersonation
    stub_session_lookup

    ImpersonationService.expects(:delete_session)
                        .with(SESSION_ID, OWNER, request_host: anything)
                        .returns({ 'status' => 'success' })

    delete "/api/v1/batch_connect/sessions/#{SESSION_ID}", headers: auth_headers

    assert_response :success
    assert_equal OWNER, JSON.parse(response.body)['user']
  end

  test 'destroy without user returns 503 instead of deleting in the wrong namespace' do
    disable_impersonation
    stub_session_lookup

    delete "/api/v1/batch_connect/sessions/#{SESSION_ID}", headers: auth_headers

    assert_response :service_unavailable
    assert_equal 'IMPERSONATION_UNAVAILABLE', JSON.parse(response.body)['code']
  end
end
