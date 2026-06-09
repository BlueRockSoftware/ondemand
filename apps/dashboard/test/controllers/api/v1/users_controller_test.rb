# frozen_string_literal: true

require 'test_helper'

class Api::V1::UsersControllerTest < ActionDispatch::IntegrationTest
  SUB = 'a1b2c3d4-0000-1111-2222-333344445555'
  EMAIL = 'casmith@jcvi.org'
  ADMIN_TOKEN = 'ood-api-admin-test'

  def auth_headers(token = ADMIN_TOKEN)
    { 'Authorization' => "Bearer #{token}" }
  end

  test 'rejects request without Authorization header' do
    post '/api/v1/users/provision', params: { sub: SUB, preferred_username: EMAIL }
    assert_response :unauthorized
  end

  test 'rejects request with an invalid token' do
    post '/api/v1/users/provision',
         params: { sub: SUB, preferred_username: EMAIL },
         headers: auth_headers('not-an-admin-token')
    assert_response :unauthorized
  end

  test 'provisions with an explicit sub and returns the canonical username' do
    UserProvisioner.expects(:call).with(preferred_username: EMAIL, sub: SUB).returns('casmith_jcvi')

    post '/api/v1/users/provision',
         params: { sub: SUB, preferred_username: EMAIL },
         headers: auth_headers
    assert_response :ok
    body = JSON.parse(response.body)
    assert_equal 'success', body['status']
    assert_equal 'casmith_jcvi', body['username']
  end

  test 'provisions by email alone (sub looked up server-side)' do
    UserProvisioner.expects(:call).with(preferred_username: EMAIL, sub: nil).returns('casmith_jcvi')

    post '/api/v1/users/provision', params: { preferred_username: EMAIL }, headers: auth_headers
    assert_response :ok
    assert_equal 'casmith_jcvi', JSON.parse(response.body)['username']
  end

  test 'returns 404 when no upstream user matches the email' do
    UserProvisioner.stubs(:call).raises(UserProvisioner::UserNotFoundError, 'no user')

    post '/api/v1/users/provision', params: { preferred_username: EMAIL }, headers: auth_headers
    assert_response :not_found
    assert_equal 'USER_NOT_FOUND', JSON.parse(response.body)['code']
  end

  test 'returns 400 when preferred_username is missing' do
    post '/api/v1/users/provision', params: { sub: SUB }, headers: auth_headers
    assert_response :bad_request
  end

  test 'returns 422 with PROVISION_FAILED when provisioning fails' do
    UserProvisioner.stubs(:call).raises(UserProvisioner::ProvisionError, 'nope')

    post '/api/v1/users/provision',
         params: { sub: SUB, preferred_username: EMAIL },
         headers: auth_headers
    assert_response :unprocessable_entity
    assert_equal 'PROVISION_FAILED', JSON.parse(response.body)['code']
  end
end
