# frozen_string_literal: true

require 'test_helper'

class UserProvisionerTest < ActiveSupport::TestCase
  SUB = 'a1b2c3d4-0000-1111-2222-333344445555'
  EMAIL = 'casmith@jcvi.org'

  def ok_status
    OpenStruct.new(success?: true, exitstatus: 0)
  end

  def fail_status
    OpenStruct.new(success?: false, exitstatus: 1)
  end

  test 'returns canonical username from user_map.py stdout' do
    Open3.expects(:capture3)
         .with({ 'OIDC_SUB' => SUB }, 'sudo', '/opt/ood/user_map.py', EMAIL)
         .returns(["casmith_jcvi\n", '', ok_status])

    assert_equal 'casmith_jcvi', UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
  end

  test 'uses only the last stdout line so log noise does not corrupt the username' do
    Open3.stubs(:capture3).returns(["INFO: provisioning\ncasmith_jcvi\n", '', ok_status])

    assert_equal 'casmith_jcvi', UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
  end

  test 'raises ProvisionError when the mapper exits non-zero' do
    Open3.stubs(:capture3).returns(['', 'boom', fail_status])

    error = assert_raises(UserProvisioner::ProvisionError) do
      UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
    end
    assert_match(/Failed to provision user/, error.message)
  end

  test 'raises ProvisionError when the mapper succeeds but prints nothing' do
    Open3.stubs(:capture3).returns(["\n", '', ok_status])

    assert_raises(UserProvisioner::ProvisionError) do
      UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
    end
  end

  test 'rejects a missing sub without invoking the mapper' do
    Open3.expects(:capture3).never

    assert_raises(UserProvisioner::ProvisionError) do
      UserProvisioner.call(sub: '', preferred_username: EMAIL)
    end
  end

  test 'rejects a malformed preferred_username without invoking the mapper' do
    Open3.expects(:capture3).never

    assert_raises(UserProvisioner::ProvisionError) do
      UserProvisioner.call(sub: SUB, preferred_username: "casmith@jcvi.org; rm -rf /")
    end
  end
end
