# frozen_string_literal: true

require 'test_helper'

class UserProvisionerTest < ActiveSupport::TestCase
  SUB = 'a1b2c3d4-0000-1111-2222-333344445555'
  EMAIL = 'casmith@jcvi.org'

  # subprocess_env requires LDAP creds in the env (bare or OOD_ alias). Provide
  # them for the tests that exercise the mapper invocation.
  LDAP_ENV = {
    'LDAP_URI' => 'ldap://openldap',
    'LDAP_BIND_DN' => 'cn=admin,dc=x',
    'LDAP_BIND_PW' => 'pw',
    'LDAP_BASE_DN' => 'dc=x'
  }.freeze

  # What the mapper must receive: the Dex-encoded form of the raw sub.
  def encoded_sub(connector = 'keycloak')
    DexSubject.encode(SUB, connector)
  end

  def ok_status
    OpenStruct.new(success?: true, exitstatus: 0)
  end

  def fail_status
    OpenStruct.new(success?: false, exitstatus: 1)
  end

  def with_ldap_env(extra = {}, &block)
    with_modified_env(LDAP_ENV.merge(extra), &block)
  end

  test 'forwards the Dex-encoded sub AND LDAP creds to user_map.py' do
    with_ldap_env do
      Open3.expects(:capture3)
           .with(
             has_entries('OIDC_SUB' => encoded_sub, 'LDAP_BIND_PW' => 'pw', 'LDAP_URI' => 'ldap://openldap'),
             'sudo', '/opt/ood/user_map.py', EMAIL
           )
           .returns(["casmith_jcvi\n", '', ok_status])

      assert_equal 'casmith_jcvi', UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
    end
  end

  test 'falls back to OOD_-prefixed env when bare LDAP_* is absent' do
    ood_env = { 'LDAP_URI' => nil, 'LDAP_BIND_DN' => nil, 'LDAP_BIND_PW' => nil, 'LDAP_BASE_DN' => nil,
                'OOD_LDAP_URI' => 'ldap://openldap', 'OOD_LDAP_BIND_DN' => 'cn=admin,dc=x',
                'OOD_LDAP_BIND_PW' => 'pw', 'OOD_LDAP_BASE_DN' => 'dc=x' }
    with_modified_env(ood_env) do
      Open3.expects(:capture3)
           .with(has_entries('LDAP_BIND_PW' => 'pw', 'LDAP_URI' => 'ldap://openldap'), 'sudo', '/opt/ood/user_map.py', EMAIL)
           .returns(["casmith_jcvi\n", '', ok_status])

      assert_equal 'casmith_jcvi', UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
    end
  end

  test 'raises a clear error when no LDAP creds are available in the env' do
    with_modified_env('LDAP_URI' => nil, 'LDAP_BIND_PW' => nil, 'OOD_LDAP_URI' => nil, 'OOD_LDAP_BIND_PW' => nil) do
      Open3.expects(:capture3).never
      error = assert_raises(UserProvisioner::ProvisionError) do
        UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
      end
      assert_match(/not available in the provisioning context/, error.message)
    end
  end

  test 'surfaces the mapper stderr in the error so the API is self-diagnosing' do
    with_ldap_env do
      Open3.stubs(:capture3).returns(['', "LDAP connection failed during resolve_by_sub\n", fail_status])
      error = assert_raises(UserProvisioner::ProvisionError) do
        UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
      end
      assert_match(/LDAP connection failed/, error.message)
    end
  end

  test 'looks up the sub by email when none is supplied' do
    with_ldap_env do
      KeycloakAdminClient.expects(:lookup_sub_by_email).with(EMAIL).returns(SUB)
      Open3.expects(:capture3)
           .with(has_entries('OIDC_SUB' => encoded_sub), 'sudo', '/opt/ood/user_map.py', EMAIL)
           .returns(["casmith_jcvi\n", '', ok_status])

      assert_equal 'casmith_jcvi', UserProvisioner.call(preferred_username: EMAIL)
    end
  end

  test 'raises UserNotFoundError when email lookup finds no Keycloak user' do
    with_ldap_env do
      KeycloakAdminClient.expects(:lookup_sub_by_email).with(EMAIL).returns(nil)
      assert_raises(UserProvisioner::UserNotFoundError) do
        UserProvisioner.call(preferred_username: EMAIL)
      end
    end
  end

  test 'raises ProvisionError when sub omitted and Keycloak lookup unconfigured' do
    with_ldap_env do
      KeycloakAdminClient.expects(:lookup_sub_by_email).raises(KeycloakAdminClient::NotConfiguredError)
      error = assert_raises(UserProvisioner::ProvisionError) do
        UserProvisioner.call(preferred_username: EMAIL)
      end
      assert_match(/not configured/, error.message)
    end
  end

  test 'uses only the last stdout line so log noise does not corrupt the username' do
    with_ldap_env do
      Open3.stubs(:capture3).returns(["INFO: provisioning\ncasmith_jcvi\n", '', ok_status])
      assert_equal 'casmith_jcvi', UserProvisioner.call(sub: SUB, preferred_username: EMAIL)
    end
  end

  test 'rejects a malformed preferred_username without invoking the mapper' do
    with_ldap_env do
      Open3.expects(:capture3).never
      assert_raises(UserProvisioner::ProvisionError) do
        UserProvisioner.call(sub: SUB, preferred_username: 'casmith@jcvi.org; rm -rf /')
      end
    end
  end
end
