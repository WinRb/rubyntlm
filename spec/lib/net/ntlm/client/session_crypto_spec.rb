# frozen_string_literal: true

RSpec.describe Net::NTLM::Client::SessionCrypto do
  let(:t2_challenge) { Net::NTLM::Message.decode64 'TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA==' }
  let(:client) { Net::NTLM::Client.new('user', 'SecREt01', domain: 'DOMAIN', workstation: 'WORKSTATION') }
  let(:inst) { Net::NTLM::Client::Session.new(client, t2_challenge) }
  let(:derived_keys) do
    %i[client_sign_key server_sign_key client_seal_key server_seal_key].map { |name| inst.send(name) }
  end
  let(:magic_constants) do
    %i[CLIENT_TO_SERVER_SIGNING SERVER_TO_CLIENT_SIGNING
       CLIENT_TO_SERVER_SEALING SERVER_TO_CLIENT_SEALING]
  end

  before do
    inst.authenticate!
  end

  # These examples deliberately stub nothing. Key derivation lives in this
  # module but is only reachable through Session, and stubbing the *_key
  # methods -- as the Session specs do -- replaces the only code that reads
  # the signing and sealing magic constants, hiding whether they resolve at
  # all. `include` shares methods, not constant lookup scope, so a constant
  # defined on Session is not reachable from a method written here.
  describe 'key derivation' do
    it 'derives a 16-byte key for each direction and purpose' do
      expect(derived_keys.map(&:bytesize)).to eq([16, 16, 16, 16])
    end

    it 'derives a distinct key for each direction and purpose' do
      expect(derived_keys.uniq.size).to eq(derived_keys.size)
    end
  end

  describe 'message protection' do
    it 'signs, seals and unseals a message using the derived keys' do
      aggregate_failures do
        expect(inst.sign_message('Test Message').bytesize).to eq(16)
        expect(inst.seal_message('rubyntlm')).not_to eq('rubyntlm')
        expect(inst.unseal_message(inst.seal_message('rubyntlm'))).to be_a(String)
      end
    end
  end

  describe 'magic constants' do
    it 'stay reachable through Session, which mixes this module in' do
      reachable = magic_constants.select { |name| Net::NTLM::Client::Session.const_defined?(name) }

      expect(reachable).to eq(magic_constants)
    end
  end
end
