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
    # The admin token is validated against ENV['OOD_INTERNAL_API_TOKEN'];
    # point it at the test token so authorized requests pass.
    @prev_admin_token = ENV['OOD_INTERNAL_API_TOKEN']
    ENV['OOD_INTERNAL_API_TOKEN'] = ADMIN_TOKEN
    controller_stubs.stubs(:get_current_pun_user).returns(ADMIN_USER)
  end

  teardown do
    ENV['OOD_INTERNAL_API_TOKEN'] = @prev_admin_token
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

  # --- create ---

  # A valid app + session stubbed at the controller boundary, so create's
  # request handling (params, validation, response shape) is exercised without
  # a real cluster.
  def stub_app_and_session(session: stub(id: 'sess-123', job_id: 'job-1', created_at: '2026-01-01T00:00:00Z'))
    app = mock('app')
    app.stubs(:valid?).returns(true)
    app.stubs(:clusters).returns([stub(id: 'cluster1')])
    context = mock('context')
    context.stubs(:attributes=)
    context.stubs(:valid?).returns(true)
    app.stubs(:build_session_context).returns(context)
    BatchConnect::App.stubs(:from_token).returns(app)
    controller_stubs.stubs(:store_volume_metadata)
    controller_stubs.stubs(:create_session_for_user).returns(session)
    app
  end

  test 'create requires authentication' do
    post '/api/v1/batch_connect/sessions',
         params: { target_user: OWNER, app_token: 'sys/bc_jupyter', context: { container: 'x' } }
    assert_response :unauthorized
  end

  test 'create returns 400 when target_user is missing' do
    post '/api/v1/batch_connect/sessions',
         params: { app_token: 'sys/bc_jupyter', context: { container: 'x' } },
         headers: auth_headers
    assert_response :bad_request
    assert_match(/target_user/, JSON.parse(response.body)['message'])
  end

  test 'create returns 400 for an invalid storage_path' do
    post '/api/v1/batch_connect/sessions',
         params: {
           target_user: OWNER, app_token: 'sys/bc_jupyter',
           context: { container: 'x' }, storage_path: '/etc/passwd'
         },
         headers: auth_headers
    assert_response :bad_request
    assert_match(/storage_path/, JSON.parse(response.body)['message'])
  end

  test 'create returns 404 when the app token is unknown' do
    BatchConnect::App.stubs(:from_token).returns(nil)
    post '/api/v1/batch_connect/sessions',
         params: { target_user: OWNER, app_token: 'sys/bogus', context: { container: 'x' } },
         headers: auth_headers
    assert_response :not_found
  end

  test 'create returns 201 with the session id and url on success' do
    stub_app_and_session
    post '/api/v1/batch_connect/sessions',
         params: { target_user: OWNER, app_token: 'sys/bc_jupyter', context: { container: 'SciPy Notebook' } },
         headers: auth_headers
    assert_response :created
    body = JSON.parse(response.body)
    assert_equal 'success', body['status']
    assert_equal 'sess-123', body['id']
    assert_equal 'sess-123', body['session_id']
    assert_equal OWNER, body['user']
    assert_equal '/batch_connect/sessions/sess-123', body['session_url']
  end

  # A valid, fresh, owned, unconsumed mount handle as returned by the Volume API
  # admin lookup. Defaults match the storage_path/volume_session_id used below.
  def valid_volume_session(id: 'vsid-9', user: OWNER, mount_path: 'volumes/vol-1', state: 'ready', container: nil)
    {
      'id' => id, 'user_id' => user, 'mount_path' => mount_path,
      'state' => state, 'container_session_id' => container, 'volume_id' => 'vol-1'
    }
  end

  test 'create echoes volume_session_id when provided' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).returns(valid_volume_session)
    post '/api/v1/batch_connect/sessions',
         params: {
           target_user: OWNER, app_token: 'sys/bc_jupyter',
           context: { container: 'SciPy Notebook' },
           storage_path: 'volumes/vol-1', volume_session_id: 'vsid-9'
         },
         headers: auth_headers
    assert_response :created
    assert_equal 'vsid-9', JSON.parse(response.body)['volume_session_id']
  end

  test 'create returns 422 when session creation yields nothing' do
    stub_app_and_session(session: nil)
    post '/api/v1/batch_connect/sessions',
         params: { target_user: OWNER, app_token: 'sys/bc_jupyter', context: { container: 'x' } },
         headers: auth_headers
    assert_response :unprocessable_entity
  end

  # --- create: volume-session validation (spec 049) ---

  def post_with_codespace(storage_path: 'volumes/vol-1', volume_session_id: 'vsid-9')
    params = {
      target_user: OWNER, app_token: 'sys/bc_jupyter',
      context: { container: 'SciPy Notebook' }
    }
    params[:storage_path] = storage_path unless storage_path.nil?
    params[:volume_session_id] = volume_session_id unless volume_session_id.nil?
    post '/api/v1/batch_connect/sessions', params: params, headers: auth_headers
  end

  test 'create rejects 422 when the volume session is not found (stale/forged)' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).returns(nil)
    post_with_codespace
    assert_response :unprocessable_entity
    assert_match(/not found or already ended/, JSON.parse(response.body)['message'])
  end

  test 'create rejects 422 when the volume session belongs to another user' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).returns(valid_volume_session(user: 'someone_else'))
    post_with_codespace
    assert_response :unprocessable_entity
    assert_match(/does not belong to target_user/, JSON.parse(response.body)['message'])
  end

  test 'create rejects 422 when mount_path does not match storage_path' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).returns(valid_volume_session(mount_path: 'volumes/OTHER'))
    post_with_codespace
    assert_response :unprocessable_entity
    assert_match(/does not match the prepared volume session/, JSON.parse(response.body)['message'])
  end

  test 'create rejects 422 when the volume session is already consumed (in_use)' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).returns(valid_volume_session(state: 'in_use', container: 'sess-prev'))
    post_with_codespace
    assert_response :unprocessable_entity
    assert_match(/already in use/, JSON.parse(response.body)['message'])
  end

  test 'create rejects 422 when storage_path is given without a volume_session_id' do
    stub_app_and_session
    VolumeApiClient.expects(:get_session).never
    post_with_codespace(volume_session_id: nil)
    assert_response :unprocessable_entity
    assert_match(/missing volume_session_id/, JSON.parse(response.body)['message'])
  end

  test 'create rejects 422 when the volume service is unavailable' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).raises(VolumeApiClient::VolumeApiError, 'boom')
    post_with_codespace
    assert_response :unprocessable_entity
    assert_match(/volume service unavailable/, JSON.parse(response.body)['message'])
  end

  test 'create succeeds 201 with a valid, owned, unconsumed volume session' do
    stub_app_and_session
    VolumeApiClient.stubs(:get_session).returns(valid_volume_session)
    post_with_codespace
    assert_response :created
    assert_equal 'vsid-9', JSON.parse(response.body)['volume_session_id']
  end

  test 'create skips volume validation entirely when no storage_path is given' do
    stub_app_and_session
    VolumeApiClient.expects(:get_session).never
    post '/api/v1/batch_connect/sessions',
         params: { target_user: OWNER, app_token: 'sys/bc_jupyter', context: { container: 'SciPy Notebook' } },
         headers: auth_headers
    assert_response :created
  end

  # --- apps ---

  # stub_everything (not mock): SysRouter.apps feeds both the apps action and
  # the global nav builder (application_controller#nav_sys_apps calls
  # should_appear_in_nav? on each), so unstubbed nav methods must no-op rather
  # than raise an unexpected-invocation error.
  def stub_app_listing(name: 'bc_jupyter', token: 'sys/bc_jupyter', type: :sys)
    app = stub_everything('listed_app')
    app.stubs(:type).returns(type)
    app.stubs(:name).returns(name)
    app.stubs(:token).returns(token)
    app.stubs(:title).returns('Jupyter')
    app.stubs(:manifest).returns(stub(description: 'Launch Jupyter'))
    app.stubs(:icon_uri).returns('/icon')
    app
  end

  test 'apps requires authentication' do
    get '/api/v1/batch_connect/sessions/apps'
    assert_response :unauthorized
  end

  test 'apps lists batch connect apps with their containers' do
    SysRouter.stubs(:apps).returns([stub_app_listing])
    controller_stubs.stubs(:extract_containers).returns([])

    get '/api/v1/batch_connect/sessions/apps', headers: auth_headers

    assert_response :success
    body = JSON.parse(response.body)
    assert_equal 'success', body['status']
    assert_equal 'sys/bc_jupyter', body['apps'].first['token']
    assert_equal [], body['apps'].first['containers']
  end

  test 'apps excludes non-sys and non-bc apps' do
    SysRouter.stubs(:apps).returns([
                                     stub_app_listing(name: 'bc_jupyter', token: 'sys/bc_jupyter', type: :sys),
                                     stub_app_listing(name: 'files', token: 'sys/files', type: :sys),
                                     stub_app_listing(name: 'bc_jupyter', token: 'usr/bc_jupyter', type: :usr)
                                   ])
    controller_stubs.stubs(:extract_containers).returns([])

    get '/api/v1/batch_connect/sessions/apps', headers: auth_headers

    assert_response :success
    tokens = JSON.parse(response.body)['apps'].map { |a| a['token'] }
    assert_equal ['sys/bc_jupyter'], tokens
  end

  # --- app_details ---

  test 'app_details requires authentication' do
    get '/api/v1/batch_connect/sessions/app_details', params: { token: 'sys/bc_jupyter' }
    assert_response :unauthorized
  end

  test 'app_details returns 400 when token is missing' do
    get '/api/v1/batch_connect/sessions/app_details', headers: auth_headers
    assert_response :bad_request
  end

  test 'app_details returns 404 for an unknown app' do
    BatchConnect::App.stubs(:from_token).returns(nil)
    get '/api/v1/batch_connect/sessions/app_details',
        params: { token: 'sys/bogus' }, headers: auth_headers
    assert_response :not_found
  end

  test 'app_details returns the app metadata and attributes' do
    app = mock('app')
    app.stubs(:valid?).returns(true)
    app.stubs(:token).returns('sys/bc_jupyter')
    app.stubs(:title).returns('Jupyter')
    app.stubs(:description).returns('Launch Jupyter')
    app.stubs(:icon_uri).returns('/icon')
    app.stubs(:attributes).returns([])
    BatchConnect::App.stubs(:from_token).returns(app)

    get '/api/v1/batch_connect/sessions/app_details',
        params: { token: 'sys/bc_jupyter' }, headers: auth_headers

    assert_response :success
    body = JSON.parse(response.body)
    assert_equal 'success', body['status']
    assert_equal 'sys/bc_jupyter', body['app']['token']
    assert_equal [], body['app']['attributes']
  end
end
