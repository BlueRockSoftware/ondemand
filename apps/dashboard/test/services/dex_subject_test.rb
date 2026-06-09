# frozen_string_literal: true

require 'test_helper'

class DexSubjectTest < ActiveSupport::TestCase
  # Golden value captured from a live LDAP entry (employeeNumber of a user who
  # logged in through Dex). If Dex's subject encoding ever changes, this breaks.
  test 'encodes a raw Keycloak sub into the Dex subject Dex itself issues' do
    encoded = DexSubject.encode('90ade737-d432-4caf-9781-0fcd32d2c775', 'keycloak')
    assert_equal 'CiQ5MGFkZTczNy1kNDMyLTRjYWYtOTc4MS0wZmNkMzJkMmM3NzUSCGtleWNsb2Fr', encoded
  end

  test 'output is base64url without padding' do
    encoded = DexSubject.encode('00000000-0000-0000-0000-000000000000', 'keycloak')
    refute_includes encoded, '='
    refute_includes encoded, '+'
    refute_includes encoded, '/'
  end

  test 'distinct connector ids produce distinct subjects' do
    a = DexSubject.encode('90ade737-d432-4caf-9781-0fcd32d2c775', 'keycloak')
    b = DexSubject.encode('90ade737-d432-4caf-9781-0fcd32d2c775', 'other')
    refute_equal a, b
  end
end
