# frozen_string_literal: true

require 'base64'

# Reproduce the OIDC `sub` that Dex issues for a federated identity.
#
# OOD authenticates through Dex, which does NOT pass an upstream IdP's `sub`
# claim through unchanged. Instead Dex marshals an `IDTokenSubject` protobuf
# `{ user_id, conn_id }` and base64url-encodes it (Go `base64.RawURLEncoding`,
# no padding). That encoded string is what Apache exposes as `OIDC_CLAIM_sub`
# and what `user_map.py` stores in LDAP `employeeNumber`.
#
# Callers that talk to the upstream IdP directly (e.g. the test-app to Keycloak)
# only have the RAW upstream `sub` (a UUID). To resolve to the SAME OOD identity
# a Dex login would, that raw sub must be re-encoded into Dex's subject format
# before it is handed to `user_map.py`. This class performs that encoding.
#
# Verified against a live entry:
#   encode("90ade737-d432-4caf-9781-0fcd32d2c775", "keycloak")
#     => "CiQ5MGFkZTczNy1kNDMyLTRjYWYtOTc4MS0wZmNkMzJkMmM3NzUSCGtleWNsb2Fr"
class DexSubject
  # Protobuf field numbers from Dex's internal.IDTokenSubject.
  USER_ID_FIELD = 1
  CONN_ID_FIELD = 2

  class << self
    # @param user_id [String] raw upstream subject (Keycloak user UUID)
    # @param conn_id [String] Dex connector id (e.g. "keycloak")
    # @return [String] Dex-issued sub (base64url, unpadded)
    def encode(user_id, conn_id)
      payload = length_delimited(USER_ID_FIELD, user_id) +
                length_delimited(CONN_ID_FIELD, conn_id)
      Base64.urlsafe_encode64(payload, padding: false)
    end

    private

    # Encode one protobuf wire-type-2 (length-delimited) field.
    def length_delimited(field_number, value)
      bytes = value.to_s.dup.force_encoding(Encoding::BINARY)
      tag = (field_number << 3) | 2 # wire type 2
      [tag].pack('C') + varint(bytes.bytesize) + bytes
    end

    # Base-128 varint, as protobuf encodes lengths.
    def varint(number)
      out = (+'').force_encoding(Encoding::BINARY)
      loop do
        byte = number & 0x7f
        number >>= 7
        byte |= 0x80 if number.positive?
        out << byte
        break unless number.positive?
      end
      out
    end
  end
end
