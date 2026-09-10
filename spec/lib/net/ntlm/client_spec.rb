# frozen_string_literal: true

RSpec.describe Net::NTLM::Client do
  let(:inst) { described_class.new('test', 'test01', workstation: 'testhost') }

  describe '#init_context' do
    let(:t2_challenge) do
      'TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUg' \
        'ACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAI' \
        'ADd7mrNaB9ABAAAAAA=='
    end
    let(:session) { instance_spy(Net::NTLM::Client::Session) }

    before do
      allow(Net::NTLM::Client::Session).to receive(:new).and_return(session)
    end

    it 'returns a Type1 message' do
      expect(inst.init_context).to be_instance_of Net::NTLM::Message::Type1
    end

    it 'sets the default domain and workstation' do
      aggregate_failures do
        t1 = inst.init_context
        expect(t1.domain).to eq('')
        expect(t1.workstation).to eq('testhost')
      end
    end

    it 'enables the default flags' do
      t1 = inst.init_context
      %i[UNICODE OEM SIGN SEAL REQUEST_TARGET NTLM ALWAYS_SIGN NTLM2_KEY KEY128 KEY_EXCHANGE KEY56].each do |flag|
        expect(t1).to have_flag(flag)
      end
    end

    it 'clears session variable on new init_context' do
      inst.instance_variable_set :@session, 'BADSESSION'
      inst.init_context
      expect(inst.session).to be_nil
    end

    it 'builds a session from the challenge message' do
      inst.init_context t2_challenge
      expect(Net::NTLM::Client::Session).to have_received(:new)
        .with(inst, instance_of(Net::NTLM::Message::Type2), nil)
    end

    it 'calls authenticate! on the session' do
      inst.init_context t2_challenge
      expect(session).to have_received(:authenticate!)
    end

    context 'with custom flags' do
      let(:flags) do
        Net::NTLM::FLAGS[:UNICODE] | Net::NTLM::FLAGS[:REQUEST_TARGET] | Net::NTLM::FLAGS[:NTLM]
      end
      let(:inst) { described_class.new('test', 'test01', workstation: 'testhost', flags: flags) }
      let(:t1) { inst.init_context }

      it 'returns a Type1 message' do
        expect(t1).to be_instance_of Net::NTLM::Message::Type1
      end

      it 'sets the domain and workstation' do
        aggregate_failures do
          expect(t1.domain).to eq('')
          expect(t1.workstation).to eq('testhost')
        end
      end

      it 'enables only the requested flags' do
        expect(t1.flag).to eq(flags)
      end
    end
  end
end
