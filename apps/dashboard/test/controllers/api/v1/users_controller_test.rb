# frozen_string_literal: true

require 'test_helper'

class Api::V1::UsersControllerTest < ActionDispatch::IntegrationTest
  SUB = 'a1b2c3d4-0000-1111-2222-333344445555'
  EMAIL = 'casmith@jcvi.org'
  ADMIN_TOKEN = 'ood-api-admin-test'

  def auth_headers(token = ADMIN_TOKEN)
    { 'Authorization' => "Bearer #{token}" }
  end

  # The admin token is validated against ENV['OOD_INTERNAL_API_TOKEN'] (the
  # chart-generated secret); point it at the test token so authorized requests
  # pass, and restore it afterwards.
  setup do
    @prev_admin_token = ENV['OOD_INTERNAL_API_TOKEN']
    ENV['OOD_INTERNAL_API_TOKEN'] = ADMIN_TOKEN
  end

  teardown do
    ENV['OOD_INTERNAL_API_TOKEN'] = @prev_admin_token
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

  test 'rejects a token with the admin prefix but the wrong secret' do
    post '/api/v1/users/provision',
         params: { sub: SUB, preferred_username: EMAIL },
         headers: auth_headers('ood-api-admin-wrong-secret')
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

  test 'returns 400 SUB_REQUIRED when sub omitted and lookup unconfigured' do
    UserProvisioner.stubs(:call).raises(UserProvisioner::SubRequiredError, 'sub is required')

    post '/api/v1/users/provision', params: { preferred_username: EMAIL }, headers: auth_headers
    assert_response :bad_request
    assert_equal 'SUB_REQUIRED', JSON.parse(response.body)['code']
  end
end
