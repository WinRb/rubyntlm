# frozen_string_literal: true

RSpec.describe Net::NTLM::Message do
  fields = []
  flags = %i[
    UNICODE
    OEM
    REQUEST_TARGET
    NTLM
    ALWAYS_SIGN
    NTLM2_KEY
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags
end
