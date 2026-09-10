# frozen_string_literal: true

RSpec.describe Net::NTLM::Int64LE do
  int_values = {
    default: 5_294_967_295,
    default_hex: [5_294_967_295 & 0x00000000ffffffff, 5_294_967_295 >> 32].pack('V2'),
    alt: 5_294_967_294,
    alt_hex: [5_294_967_294 & 0x00000000ffffffff, 5_294_967_294 >> 32].pack('V2'),
    small: "\x5C\x24\x10\x0f",
    size: 8,
    bits: 64,
    error: NoMethodError
  }

  it_behaves_like 'a field', 252_716_124, false
  it_behaves_like 'an integer field', int_values
end
