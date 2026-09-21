# frozen_string_literal: true

RSpec.describe Net::NTLM::ChannelBinding do
  subject(:channel_binding) { described_class.create(sha_256_cert) }

  let(:certificates_path) { 'spec/support/certificates' }
  let(:sha_256_path) { File.join(certificates_path, 'sha_256_hash.pem') }
  let(:sha_256_cert) { OpenSSL::X509::Certificate.new(File.read(sha_256_path)) }
  let(:cert_hash) do
    "\x04\x0E\x56\x28\xEC\x4A\x98\x29\x91\x70\x73\x62\x03\x7B\xB2\x3C".dup.force_encoding(Encoding::ASCII_8BIT)
  end

  describe '#channel_binding_token' do
    it 'returns the correct hash' do
      expect(channel_binding.channel_binding_token).to eq cert_hash
    end
  end

  describe '#channel_hash' do
    # RFC 5929 section 4.1: the tls-server-end-point hash follows the
    # certificate's own signature algorithm (MD5/SHA-1 upgrade to SHA-256).
    {
      'sha_256_hash.pem' => OpenSSL::Digest::SHA256,
      'sha_384_hash.pem' => OpenSSL::Digest::SHA384,
      'sha_512_hash.pem' => OpenSSL::Digest::SHA512,
      'sha_1_hash.pem'   => OpenSSL::Digest::SHA256
    }.each do |fixture, digest_class|
      context "with a #{fixture.delete_suffix('_hash.pem').tr('_', '-')} signed certificate" do
        it "hashes the certificate with #{digest_class.name}" do
          cert = OpenSSL::X509::Certificate.new(
            File.read(File.join('spec/support/certificates', fixture))
          )
          binding = described_class.create(cert)

          expect(binding.channel_hash.digest).to eq digest_class.new(cert.to_der).digest
        end
      end
    end
  end
end
