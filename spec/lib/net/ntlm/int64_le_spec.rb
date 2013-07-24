require 'spec_helper'

describe Net::NTLM::Int64LE do

  int_values = {
      :default     => 5294967295,
      :default_hex => "\xFF\xC9\x9A;\x01\x00\x00\x00",
      :alt         => 5294967294,
      :alt_hex     => "\xFE\xC9\x9A;\x01\x00\x00\x00",
      :small       => "\x5C\x24\x10\x0f",
      :size        => 8,
      :bits        => 64
  }


  it_behaves_like 'a field', 252716124, false
  it_behaves_like 'an integer field', int_values

end