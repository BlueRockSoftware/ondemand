# frozen_string_literal: true

require 'test_helper'

# Regression guard: now that Volume API reclamation keys off volume_session_id
# (spec 049, FR-007), the teardown webhook MUST keep forwarding it (FR-013).
class VolumeWebhookServiceTest < ActiveSupport::TestCase
  test 'build_payload forwards volume_session_id and container_session_id' do
    session = stub(id: 'container-1', info: stub(to_h: { volume_session_id: 'vsid-7' }))

    payload = VolumeWebhookService.send(:build_payload, session, 'vsid-7', 'cancelled', nil, nil)

    assert_equal 'vsid-7', payload[:volume_session_id]
    assert_equal 'container-1', payload[:container_session_id]
    assert_equal 'cancelled', payload[:exit_status]
  end

  test 'session_volume_id falls back to user_context when info lacks it' do
    session = stub(info: stub(to_h: {}), user_context: { 'volume_session_id' => 'vsid-ctx' })
    assert_equal 'vsid-ctx', VolumeWebhookService.send(:session_volume_id, session)
  end

  test 'session_storage_path reads from info or user_context' do
    s_info = stub(info: stub(to_h: { storage_path: 'p1' }), user_context: {})
    assert_equal 'p1', VolumeWebhookService.send(:session_storage_path, s_info)
    s_ctx = stub(info: stub(to_h: {}), user_context: { 'storage_path' => 'p2' })
    assert_equal 'p2', VolumeWebhookService.send(:session_storage_path, s_ctx)
  end

  # FR-007: a codespace session with only storage_path (no recoverable
  # volume_session_id) must still fire — the Volume API reclaims by the
  # container_session_id the launch linked onto the handle.
  test 'send_session_ended fires for a codespace with only storage_path' do
    session = stub(id: 'container-9', info: stub(to_h: { storage_path: 'mnt/p' }), user_context: {})
    VolumeWebhookService.expects(:send_webhook_async).once
    with_modified_env('VOLUME_API_URL' => 'https://volume-api.test') do
      VolumeWebhookService.send_session_ended(session, 'cancelled')
    end
  end

  test 'send_session_ended skips a non-codespace session (no markers)' do
    session = stub(id: 'container-x', info: stub(to_h: {}), user_context: {})
    VolumeWebhookService.expects(:send_webhook_async).never
    with_modified_env('VOLUME_API_URL' => 'https://volume-api.test') do
      VolumeWebhookService.send_session_ended(session, 'cancelled')
    end
  end
end
