# frozen_string_literal: true

require 'test_helper'

class UserProvisionerTest < ActiveSupport::TestCase
  SUB = 'a1b2c3d4-0000-1111-2222-333344445555'
  EMAIL = 'casmith@jcvi.org'

  # What the mapper must receive: the Dex-encoded form of the raw sub, NOT the
  # raw sub -- so API-provisioned users match interactive Dex logins.
  def encoded_sub(connector = 'keycloak')
    DexSubject.encode(SUB, connector)
  end

  def ok_status
    OpenStruct.new(success?: true, exitstatus: 0)
  end

  def fail_status
    OpenStruct.new(success?: false, exitstatus: 1)
  end

  test 'passes the Dex-encoded sub (not the raw sub) to user_map.py' do
    Open3.expects(:capture3)
         .with({ 'OIDC_SUB' => encoded_sub }, 'sudo', '/opt/ood/user_map.py', EMAIL)
         .returns(["casmith_jcvi\n", '', ok_status])

    assert_equal 'casmith_jcvi', UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
  end

  test 'honors a custom connector id when encoding the sub' do
    Open3.expects(:capture3)
         .with({ 'OIDC_SUB' => encoded_sub('other') }, 'sudo', '/opt/ood/user_map.py', EMAIL)
         .returns(["casmith_jcvi\n", '', ok_status])

    UserProvisioner.call(sub: SUB, preferred_username: EMAIL, connector_id: 'other')
  end

  test 'looks up the sub by email when none is supplied' do
    KeycloakAdminClient.expects(:lookup_sub_by_email).with(EMAIL).returns(SUB)
    Open3.expects(:capture3)
         .with({ 'OIDC_SUB' => encoded_sub }, 'sudo', '/opt/ood/user_map.py', EMAIL)
         .returns(["casmith_jcvi\n", '', ok_status])

    assert_equal 'casmith_jcvi', UserProvisioner.call(preferred_username: EMAIL)
  end

  test 'raises UserNotFoundError when email lookup finds no Keycloak user' do
    KeycloakAdminClient.expects(:lookup_sub_by_email).with(EMAIL).returns(nil)
    Open3.expects(:capture3).never

    assert_raises(UserProvisioner::UserNotFoundError) do
      UserProvisioner.call(preferred_username: EMAIL)
    end
  end

  test 'raises ProvisionError when sub omitted and Keycloak lookup unconfigured' do
    KeycloakAdminClient.expects(:lookup_sub_by_email)
                       .raises(KeycloakAdminClient::NotConfiguredError)
    Open3.expects(:capture3).never

    error = assert_raises(UserProvisioner::ProvisionError) do
      UserProvisioner.call(preferred_username: EMAIL)
    end
    assert_match(/not configured/, error.message)
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

  test 'rejects a malformed preferred_username without invoking the mapper' do
    Open3.expects(:capture3).never

    assert_raises(UserProvisioner::ProvisionError) do
      UserProvisioner.call(sub: SUB, preferred_username: 'casmith@jcvi.org; rm -rf /')
    end
  end
end
