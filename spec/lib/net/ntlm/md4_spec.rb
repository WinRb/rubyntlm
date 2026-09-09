RSpec.describe Net::NTLM::Md4 do
  describe '.digest' do
    it 'hashes binary input containing high bytes' do
      # Independently calculated with OpenSSL's legacy MD4 provider.
      expect(described_class.digest("\xff".b).unpack('H*').first).
        to eq('82c167af8e345bd055487af8d2b540c9')
    end

    it 'preserves the caller input and encoding' do
      input = "\xff".b.freeze
      described_class.digest(input)
      expect(input).to eq("\xff".b)
      expect(input.encoding).to eq(Encoding::ASCII_8BIT)
    end
  end
end
