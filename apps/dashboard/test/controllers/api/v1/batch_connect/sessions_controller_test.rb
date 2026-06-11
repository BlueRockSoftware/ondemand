# frozen_string_literal: true

require 'test_helper'
require 'tmpdir'
require 'fileutils'
require 'ostruct'

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

  # --- index (unfiltered list) ---
  #
  # These tests build a real dataroot in a tmpdir (the path must contain an
  # 'ood-home' component for extract_username_from_path) so the scan, owner
  # grouping, and merge logic run for real; only the PUN forwarding and the
  # current-user identity are stubbed.

  def with_dataroot
    Dir.mktmpdir do |tmp|
      base = File.join(tmp, 'ood-home')
      FileUtils.mkdir_p(base)
      controller_stubs.stubs(:get_base_dataroot).returns(Pathname.new(base))
      yield base
    end
  end

  def write_session_db(base, user, id, cache_completed: nil)
    dir = File.join(base, user, 'ondemand', 'data', 'sys', 'dashboard', 'batch_connect', 'db')
    FileUtils.mkdir_p(dir)
    data = { id: id, cluster_id: 'k8s', job_id: "jupyter-#{id}", created_at: 1,
             token: 'sys/bc_jupyter', title: 'Jupyter', script_type: 'basic',
             cache_completed: cache_completed, completed_at: nil }
    File.write(File.join(dir, id), data.to_json)
  end

  def live_entry(user, id, status, project: nil)
    session = OpenStruct.new(id: id, job_id: "jupyter-#{id}", title: 'Jupyter',
                             created_at: 1, cluster_id: 'k8s', token: 'sys/bc_jupyter')
    session.define_singleton_method(:user_context) { { 'project' => project } }
    session.define_singleton_method(:completed?) { status == 'completed' }
    session.define_singleton_method(:running?) { status == 'running' }
    session.define_singleton_method(:queued?) { status == 'queued' }
    { user: user, session: session }
  end

  def sessions_by_id
    JSON.parse(response.body)['sessions'].index_by { |s| s['id'] }
  end

  test 'index resolves cross-user statuses via per-owner impersonation' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, OWNER, 'live1')

      ImpersonationService.expects(:list_sessions)
                          .with(OWNER, request_host: anything)
                          .returns([live_entry(OWNER, 'live1', 'running')])

      get '/api/v1/batch_connect/sessions', headers: auth_headers

      assert_response :success
      entry = sessions_by_id.fetch('live1')
      assert_equal 'running', entry['status']
      assert_equal 'live', entry['status_source']
      assert_equal OWNER, entry['user']
    end
  end

  test 'index does not wake PUNs for owners whose sessions are all latched completed' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, OWNER, 'dead1', cache_completed: true)
      write_session_db(base, OWNER, 'dead2', cache_completed: true)

      ImpersonationService.expects(:list_sessions).never

      get '/api/v1/batch_connect/sessions', headers: auth_headers

      assert_response :success
      sessions_by_id.values_at('dead1', 'dead2').each do |entry|
        assert_equal 'completed', entry['status']
        assert_equal 'cached', entry['status_source']
      end
    end
  end

  test 'index degrades an owner to cached statuses when their PUN listing fails' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, OWNER, 'latched', cache_completed: true)
      write_session_db(base, OWNER, 'active')

      ImpersonationService.expects(:list_sessions).returns(nil)

      get '/api/v1/batch_connect/sessions', headers: auth_headers

      assert_response :success
      entries = sessions_by_id
      assert_equal %w[completed cached], entries.fetch('latched').values_at('status', 'status_source')
      assert_equal %w[unknown unknown], entries.fetch('active').values_at('status', 'status_source')
    end
  end

  test 'index merges live results and keeps only latched leftovers' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, OWNER, 'kept', cache_completed: true)
      write_session_db(base, OWNER, 'reaped')
      write_session_db(base, OWNER, 'live1')

      ImpersonationService.expects(:list_sessions)
                          .returns([live_entry(OWNER, 'live1', 'queued')])

      get '/api/v1/batch_connect/sessions', headers: auth_headers

      assert_response :success
      entries = sessions_by_id
      assert_equal %w[queued live], entries.fetch('live1').values_at('status', 'status_source')
      assert_equal %w[completed cached], entries.fetch('kept').values_at('status', 'status_source')
      refute entries.key?('reaped'), 'non-latched session absent from live response should be dropped'
    end
  end

  test 'index never evaluates cross-user sessions when impersonation token is blank' do
    PunManager.stubs(:impersonation_enabled?).returns(true)
    PunManager.stubs(:internal_api_token).returns(nil)
    with_dataroot do |base|
      write_session_db(base, OWNER, 'active')

      get '/api/v1/batch_connect/sessions', headers: auth_headers

      assert_response :success
      assert_equal %w[unknown unknown], sessions_by_id.fetch('active').values_at('status', 'status_source')
    end
  end

  test 'index with live=false skips the PUN fan-out entirely' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, OWNER, 'active')
      write_session_db(base, OWNER, 'latched', cache_completed: true)

      ImpersonationService.expects(:list_sessions).never

      get '/api/v1/batch_connect/sessions', params: { live: 'false' }, headers: auth_headers

      assert_response :success
      entries = sessions_by_id
      assert_equal %w[unknown unknown], entries.fetch('active').values_at('status', 'status_source')
      assert_equal %w[completed cached], entries.fetch('latched').values_at('status', 'status_source')
    end
  end

  test 'index evaluates the current PUN user sessions locally as live' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, ADMIN_USER, 'own1')

      ImpersonationService.expects(:list_sessions).never

      get '/api/v1/batch_connect/sessions', headers: auth_headers

      assert_response :success
      entry = sessions_by_id.fetch('own1')
      assert_equal 'live', entry['status_source']
      assert_equal ADMIN_USER, entry['user']
    end
  end

  test 'filtered list reports cached statuses when forwarding fails' do
    enable_impersonation
    with_dataroot do |base|
      write_session_db(base, OWNER, 'active')
      controller_stubs.stubs(:get_user_dataroot)
                      .returns(Pathname.new(File.join(base, OWNER, 'ondemand', 'data', 'sys', 'dashboard')))

      ImpersonationService.expects(:list_sessions).returns(nil)

      get '/api/v1/batch_connect/sessions', params: { user: OWNER }, headers: auth_headers

      assert_response :success
      assert_equal %w[unknown unknown], sessions_by_id.fetch('active').values_at('status', 'status_source')
    end
  end
end
