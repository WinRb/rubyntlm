# frozen_string_literal: true

RSpec.describe Net::NTLM::Client::Session do
  let(:t2_challenge) { Net::NTLM::Message.decode64 'TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA==' }
  let(:inst) { described_class.new(nil, t2_challenge) }
  let(:keys) do
    {
      user_session: ['3c4918ff0b33e2603e5d7ceaf34bb7d5'].pack('H*'),
      client_sign: ['f7f97a82ec390f9c903dac4f6aceb132'].pack('H*'),
      client_seal: ['6f0d99535033951cbe499cd1914fe9ee'].pack('H*'),
      server_sign: ['f7f97a82ec390f9c903dac4f6aceb132'].pack('H*'),
      server_seal: ['6f0d99535033951cbe499cd1914fe9ee'].pack('H*')
    }
  end

  def expect_received(*messages)
    aggregate_failures do
      messages.each { |message| expect(inst).to have_received(message) }
    end
  end

  describe '#sign_message' do
    before do
      allow(inst).to receive_messages(
        client_sign_key: keys[:client_sign],
        client_seal_key: keys[:client_seal],
        negotiate_key_exchange?: true
      )
    end

    it 'signs a message and when KEY_EXCHANGE is true' do
      sm = inst.sign_message('Test Message')
      expect(sm.unpack1('H*')).to eq('01000000b35ccd60c110c52f00000000')
      expect_received(:client_sign_key, :client_seal_key, :negotiate_key_exchange?)
    end
  end

  describe '#verify_signature' do
    before do
      allow(inst).to receive_messages(
        server_sign_key: keys[:server_sign],
        server_seal_key: keys[:server_seal],
        negotiate_key_exchange?: true
      )
    end

    it 'verifies a message signature' do
      sig = '01000000b35ccd60c110c52f00000000'
      sm = inst.verify_signature([sig].pack('H*'), 'Test Message')
      expect(sm).to be true
      expect_received(:server_sign_key, :server_seal_key, :negotiate_key_exchange?)
    end
  end

  describe '#seal_message' do
    before do
      allow(inst).to receive(:client_seal_key).and_return(keys[:client_seal])
    end

    it 'seals the message' do
      emsg = inst.seal_message('rubyntlm')
      aggregate_failures do
        expect(emsg.unpack1('H*')).to eq('d7389b9604f6274f')
        expect(inst).to have_received(:client_seal_key)
      end
    end
  end

  describe '#unseal_message' do
    before do
      allow(inst).to receive(:server_seal_key).and_return(keys[:server_seal])
    end

    it 'unseals the message' do
      msg = inst.unseal_message(['d7389b9604f6274f'].pack('H*'))
      aggregate_failures do
        expect(msg).to eq('rubyntlm')
        expect(inst).to have_received(:server_seal_key)
      end
    end
  end

  describe '#exported_session_key' do
    let(:key_exchange) { true }

    before do
      allow(inst).to receive_messages(
        negotiate_key_exchange?: key_exchange,
        user_session_key: keys[:user_session]
      )
    end

    it 'returns a random 16-byte key when negotiate_key_exchange? is true' do
      inst.exported_session_key
      expect_received(:negotiate_key_exchange?)
      expect(inst).not_to have_received(:user_session_key)
    end

    context 'when key exchange is not negotiated' do
      let(:key_exchange) { false }

      it 'returns the user_session_key' do
        expect(inst.exported_session_key).to eq(keys[:user_session])
        expect_received(:negotiate_key_exchange?, :user_session_key)
      end
    end
  end

  context 'when authenticating anonymously' do
    let(:inst) { described_class.new(Net::NTLM::Client.new('', ''), t2_challenge) }

    describe '#authenticate!' do
      let(:t3) { inst.authenticate! }

      it 'sets the response fields correctly' do
        aggregate_failures do
          expect(t3).to be_a(Net::NTLM::Message::Type3)
          expect(t3.lm_response).to eq("\x00".b)
          expect(t3.ntlm_response).to eq('')
        end
      end
    end

    describe '#is_anonymous?' do
      it 'is true' do
        expect(inst).to be_is_anonymous
      end
    end
  end
end
