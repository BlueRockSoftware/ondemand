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
end
