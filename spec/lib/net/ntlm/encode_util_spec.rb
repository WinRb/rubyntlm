# frozen_string_literal: true

RSpec.describe Net::NTLM::EncodeUtil do
  describe '#encode_utf16le' do
    it 'converts an ASCII string to UTF' do
      expect(described_class.encode_utf16le('Test'.encode(::Encoding::ASCII_8BIT))).to eq("T\x00e\x00s\x00t\x00")
    end
  end

  describe '#decode_utf16le' do
    it 'converts a UTF string to ASCII' do
      expect(described_class.decode_utf16le("T\x00e\x00s\x00t\x00")).to eq('Test')
    end
  end
end
