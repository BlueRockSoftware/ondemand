# frozen_string_literal: true

require 'test_helper'

class KeycloakAdminClientTest < ActiveSupport::TestCase
  ENV_OK = {
    'KEYCLOAK_URL' => 'https://keycloak.example.org',
    'KEYCLOAK_REALM' => 'abcd',
    'KEYCLOAK_ADMIN_CLIENT_ID' => 'ood-admin',
    'KEYCLOAK_ADMIN_CLIENT_SECRET' => 'shh'
  }.freeze

  def http_ok(body)
    res = Net::HTTPOK.new('1.1', '200', 'OK')
    res.instance_variable_set(:@read, true)
    res.define_singleton_method(:body) { body }
    res
  end

  test 'configured? is false when env is missing' do
    with_modified_env('KEYCLOAK_URL' => nil, 'KEYCLOAK_REALM' => nil,
                      'KEYCLOAK_ADMIN_CLIENT_ID' => nil, 'KEYCLOAK_ADMIN_CLIENT_SECRET' => nil) do
      refute KeycloakAdminClient.configured?
    end
  end

  test 'lookup raises NotConfiguredError when unconfigured' do
    with_modified_env('KEYCLOAK_URL' => nil, 'KEYCLOAK_REALM' => nil,
                      'KEYCLOAK_ADMIN_CLIENT_ID' => nil, 'KEYCLOAK_ADMIN_CLIENT_SECRET' => nil) do
      assert_raises(KeycloakAdminClient::NotConfiguredError) do
        KeycloakAdminClient.lookup_sub_by_email('casmith@jcvi.org')
      end
    end
  end

  test 'lookup returns the user id (raw sub) for a matching email' do
    with_modified_env(ENV_OK) do
      Net::HTTP.any_instance.stubs(:request)
               .returns(http_ok({ access_token: 'tok' }.to_json))
               .then.returns(http_ok([{ 'id' => 'raw-sub-1', 'email' => 'casmith@jcvi.org' }].to_json))

      assert_equal 'raw-sub-1', KeycloakAdminClient.lookup_sub_by_email('casmith@jcvi.org')
    end
  end

  test 'lookup returns nil when no user matches' do
    with_modified_env(ENV_OK) do
      Net::HTTP.any_instance.stubs(:request)
               .returns(http_ok({ access_token: 'tok' }.to_json))
               .then.returns(http_ok([].to_json))

      assert_nil KeycloakAdminClient.lookup_sub_by_email('nobody@jcvi.org')
    end
  end
end
