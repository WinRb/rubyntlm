# frozen_string_literal: true

RSpec.describe Net::NTLM::Int32LE do
  int_values = {
    default: 252_716_124,
    default_hex: "\x5C\x24\x10\x0f",
    alt: 235_938_908,
    alt_hex: "\x5C\x24\x10\x0e",
    small: "\x0F\x00",
    size: 4,
    bits: 32,
    error: TypeError
  }

  it_behaves_like 'a field', 252_716_124, false
  it_behaves_like 'an integer field', int_values
end
