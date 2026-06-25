# frozen_string_literal: true

require 'test_helper'

# The Admin API delete is forwarded here via impersonation, so this internal
# path -- not the admin controller's local path -- is what runs for codespace
# teardowns. It must fire the volume session-ended webhook so the mount handle
# is reclaimed (spec 049, FR-007); otherwise the volume_session_id survives and
# can be reused on the next launch.
class Internal::BatchConnect::SessionsControllerTest < ActionDispatch::IntegrationTest
  def controller_stubs
    Internal::BatchConnect::SessionsController.any_instance
  end

  setup do
    # Bypass the localhost + internal-token gates; this suite exercises destroy
    # behavior, not the access guards.
    controller_stubs.stubs(:verify_internal_access)
    controller_stubs.stubs(:verify_internal_token)
    OodSupport::User.stubs(:new).returns(stub(name: 'tuser'))
    VolumeWebhookService.stubs(:determine_exit_status).returns('cancelled')
  end

  test 'destroy fires the volume session-ended webhook before destroying' do
    session = stub_everything('session')
    controller_stubs.stubs(:find_owned_session).returns(session)

    VolumeWebhookService.expects(:send_session_ended).once

    delete '/internal/batch_connect/sessions/abc-123'
    assert_response :success
  end

  test 'destroy still succeeds when the webhook raises (fire-and-forget)' do
    session = stub_everything('session')
    controller_stubs.stubs(:find_owned_session).returns(session)
    VolumeWebhookService.stubs(:send_session_ended).raises(StandardError.new('boom'))

    delete '/internal/batch_connect/sessions/abc-123'
    assert_response :success
  end

  test 'destroy sends no webhook and 404s when the session is absent' do
    controller_stubs.stubs(:find_owned_session).returns(nil)
    VolumeWebhookService.expects(:send_session_ended).never

    delete '/internal/batch_connect/sessions/missing'
    assert_response :not_found
  end

  # G1: impersonated create runs here, so this path -- not the admin controller's
  # store_volume_metadata (which can't reach this session's info) -- must persist
  # volume_session_id, or the teardown webhook later finds nothing to forward.
  test 'create persists volume_session_id onto the session info' do
    app = stub('app', valid?: true)
    context = stub('context', valid?: true)
    context.stubs(:attributes=)
    app.stubs(:build_session_context).returns(context)
    ::BatchConnect::App.stubs(:from_token).returns(app)

    session = mock('session')
    session.stubs(:save).returns(true)
    session.stubs(:info).returns({})
    session.stubs(:id).returns('sess-1')
    session.stubs(:job_id).returns('job-1')
    session.stubs(:created_at).returns(Time.now)
    # The assertion: the volume_session_id is written back onto the session info.
    session.expects(:info=).with { |i| i[:volume_session_id] == 'vsid-9' }
    session.stubs(:respond_to?).with(:info=).returns(true)
    ::BatchConnect::Session.stubs(:new).returns(session)

    post '/internal/batch_connect/sessions',
         params: { app_token: 'sys/bc_jupyter', context: { cluster: 'x' },
                   storage_path: 'mnt/p', volume_session_id: 'vsid-9' }
    assert_response :created
  end
end
