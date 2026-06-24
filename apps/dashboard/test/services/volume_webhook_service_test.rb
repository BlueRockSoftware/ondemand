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
end
