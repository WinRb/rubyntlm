# frozen_string_literal: true

RSpec.describe Net::NTLM::Message::Type3 do
  fields = [
    { name: :sign, class: Net::NTLM::String, value: Net::NTLM::SSP_SIGN, active: true },
    { name: :type, class: Net::NTLM::Int32LE, value: 3, active: true },
    { name: :lm_response, class: Net::NTLM::SecurityBuffer, value: '', active: true },
    { name: :ntlm_response, class: Net::NTLM::SecurityBuffer, value: '', active: true },
    { name: :domain, class: Net::NTLM::SecurityBuffer, value: '', active: true },
    { name: :user, class: Net::NTLM::SecurityBuffer, value: '', active: true },
    { name: :workstation, class: Net::NTLM::SecurityBuffer, value: '', active: true },
    { name: :session_key, class: Net::NTLM::SecurityBuffer, value: '', active: false },
    { name: :flag, class: Net::NTLM::Int32LE, value: 0, active: false }
  ]
  flags = []
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

  describe '.parse' do
    subject(:message) { described_class.parse(data) }

    context 'with NTLMv2 data' do
      let(:data) do
        # Captured NTLMSSP blob from smbclient with username 'administrator'
        # and a blank password, i.e.:
        #   smbclient -U 'administrator%' -L //192.168.100.140/
        [
          '4e544c4d53535000030000001800180040000000c400c4005800000012001200' \
          '1c0100001a001a002e0100001a001a0048010000100010006201000015820860' \
          'ced203d860b80c7350050754b238202a8c1c63134f0ae0f086a3fb147e8b2f9f' \
          'de3ef1b1b43c83dc010100000000000080512dba020ed0011c5bc2c8339fd29a' \
          '0000000002001e00570049004e002d00420035004a004e003300520048004700' \
          '46003300310001001e00570049004e002d00420035004a004e00330052004800' \
          '470046003300310004001e00570049004e002d00420035004a004e0033005200' \
          '4800470046003300310003001e00570049004e002d00420035004a004e003300' \
          '52004800470046003300310007000800a209e5ba020ed0010000000057004f00' \
          '52004b00470052004f0055005000610064006d0069006e006900730074007200' \
          '610074006f0072004100550053002d004c004500450054002d00310030003300' \
          '31007036615cd6d9b19a685ded4312311cd7'
        ].pack('H*')
      end

      let(:server_challenge) { ['f588469dc96fe809'].pack('H*') }
      let(:expected_ntlm_response) do
        [
          '86a3fb147e8b2f9fde3ef1b1b43c83dc010100000000000080512dba020ed001' \
          '1c5bc2c8339fd29a0000000002001e00570049004e002d00420035004a004e00' \
          '330052004800470046003300310001001e00570049004e002d00420035004a00' \
          '4e00330052004800470046003300310004001e00570049004e002d0042003500' \
          '4a004e00330052004800470046003300310003001e00570049004e002d004200' \
          '35004a004e00330052004800470046003300310007000800a209e5ba020ed001' \
          '00000000'
        ].pack('H*')
      end

      it 'sets the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end

      it 'sets the type' do
        expect(message.type).to eq(3)
      end

      it 'sets the LM response' do
        lm_response = ['ced203d860b80c7350050754b238202a8c1c63134f0ae0f0'].pack('H*')
        expect(message.lm_response).to eq(lm_response)
      end

      it 'sets the NTLM response' do
        expect(message.ntlm_response).to eq(expected_ntlm_response)
      end

      it 'sets the user' do
        # administrator
        user = ['610064006d0069006e006900730074007200610074006f007200'].pack('H*')
        expect(message.user).to eq(user)
      end

      it 'sets the domain' do
        # WORKGROUP
        domain = ['57004f0052004b00470052004f0055005000'].pack('H*')
        expect(message.domain).to eq(domain)
      end

      it 'sets the workstation' do
        # AUS-LEET-1031
        workstation = ['4100550053002d004c004500450054002d003100300033003100'].pack('H*')
        expect(message.workstation).to eq(workstation)
      end

      it 'sets the session key' do
        session_key = ['7036615cd6d9b19a685ded4312311cd7'].pack('H*')
        expect(message.session_key).to eq(session_key)
      end

      it 'sets the flags' do
        expect(message.flag).to eq(0x60088215)
      end

      it 'does not set the OS version structure' do
        expect(message.os_version).to be_nil
      end

      it '#blank_password? is true' do
        expect(message.blank_password?(server_challenge)).to be true
      end

      it 'rejects a non-empty password for an empty-password response' do
        expect(message.password?('test1234', server_challenge)).to be false
      end

      it '#ntlm_version is :ntlmv2' do
        expect(message.ntlm_version).to eq(:ntlmv2)
      end
    end

    # http://davenport.sourceforge.net/ntlm.html#appendixC7
    context 'NTLM2 Session Response Authentication; NTLM2 Signing and Sealing Using the 128-bit NTLM2 Session Re' \
        'sponse User Session Key With Key Exchange Negotiated' do
      let(:data) do
        [
          '4e544c4d5353500003000000180018006000000018001800780000000c000c00' \
          '40000000080008004c0000000c000c00540000001000100090000000358288e0' \
          '54004500530054004e00540074006500730074004d0045004d00420045005200' \
          '404d1b6f6915258000000000000000000000000000000000ea8cc49f24da157f' \
          '13436637f77693d8b992d619e584c7ee727a5240822ec7af4e9100c43e6fee7f'
        ].pack('H*')
      end

      let(:server_challenge) { ['677f1c557a5ee96c'].pack('H*') }

      it 'sets the LM response' do
        lm_response = ['404d1b6f6915258000000000000000000000000000000000'].pack('H*')
        expect(message.lm_response).to eq(lm_response)
      end

      it 'sets the NTLM response' do
        ntlm_response = ['ea8cc49f24da157f13436637f77693d8b992d619e584c7ee'].pack('H*')
        expect(message.ntlm_response).to eq(ntlm_response)
      end

      it 'sets the domain' do
        # TESTNT
        domain = ['54004500530054004e005400'].pack('H*')
        expect(message.domain).to eq(domain)
      end

      it 'sets the user' do
        # test
        user = ['7400650073007400'].pack('H*')
        expect(message.user).to eq(user)
      end

      it 'sets the workstation' do
        # MEMBER
        workstation = ['4d0045004d00420045005200'].pack('H*')
        expect(message.workstation).to eq(workstation)
      end

      it 'sets the session key' do
        session_key = ['727a5240822ec7af4e9100c43e6fee7f'].pack('H*')
        expect(message.session_key).to eq(session_key)
      end

      it '#password? is true for "test1234"' do
        expect(message.password?('test1234', server_challenge)).to be true
      end

      it '#blank_password? is false' do
        expect(message.blank_password?(server_challenge)).to be false
      end

      it '#ntlm_version is :ntlm2_session' do
        expect(message.ntlm_version).to eq(:ntlm2_session)
      end
    end

    # http://davenport.sourceforge.net/ntlm.html#appendixC9
    context 'NTLMv2 Authentication; NTLM1 Signing and Sealing Using the 40-bit NTLMv2 User Session Key' do
      let(:server_challenge) { ['0033b02d17275b77'].pack('H*') }
      let(:expected_ntlm_response) do
        [
          'f77c67dad00b93216242b197fe6addfa0101000000000000502db638677bc301' \
          'f2e6329726c598e80000000002000c0054004500530054004e00540001000c00' \
          '4d0045004d0042004500520003001e006d0065006d006200650072002e007400' \
          '6500730074002e0063006f006d000000000000000000'
        ].pack 'H*'
      end

      let(:data) do
        [
          '4e544c4d5353500003000000180018006000000076007600780000000c000c00' \
          '40000000080008004c0000000c000c005400000000000000ee00000035828000' \
          '54004500530054004e00540074006500730074004d0045004d00420045005200' \
          '5d55a02b60a40526ac9a1e4d15fa45a0f2e6329726c598e8f77c67dad00b9321' \
          '6242b197fe6addfa0101000000000000502db638677bc301f2e6329726c598e8' \
          '0000000002000c0054004500530054004e00540001000c004d0045004d004200' \
          '4500520003001e006d0065006d006200650072002e0074006500730074002e00' \
          '63006f006d000000000000000000'
        ].pack 'H*'
      end

      it '#password? accepts the known fixture password' do
        expect(message.password?('test1234', server_challenge)).to be true
      end

      it '#password? rejects an incorrect password' do
        expect(message.password?('wrong', server_challenge)).to be false
      end

      it '#blank_password? rejects an empty password' do
        expect(message.blank_password?(server_challenge)).to be false
      end

      it 'sets the NTLM response' do
        expect(message.ntlm_response).to eq(expected_ntlm_response)
      end

      it 'sets the domain' do
        # TESTNT
        domain = ['54004500530054004e005400'].pack('H*')
        expect(message.domain).to eq(domain)
      end

      it 'sets the user' do
        # test
        user = ['7400650073007400'].pack('H*')
        expect(message.user).to eq(user)
      end

      it 'sets the workstation' do
        # MEMBER
        workstation = ['4d0045004d00420045005200'].pack('H*')
        expect(message.workstation).to eq(workstation)
      end

      it '#ntlm_version is :ntlmv2' do
        expect(message.ntlm_version).to eq(:ntlmv2)
      end
    end
  end

  describe '#password? with serialized NTLMv2 responses' do
    subject(:message) do
      described_class.parse(type2.response(
        { user: 'victim', domain: 'CORP', password: password },
        { ntlmv2: true, client_challenge: 0x1122334455667788, timestamp: 0 }
      ).serialize)
    end

    let(:type2) do
      Net::NTLM::Message::Type2.new.tap do |message|
        message.challenge = 0x0123456789abcdef
      end
    end
    let(:server_challenge) { Net::NTLM.pack_int64le(type2.challenge) }

    ['secret', 'odd', "p\u00e4ss\u5bc6\u7801\u{1f512}", ''].each do |password|
      context "with password #{password.inspect}" do
        let(:password) { password }

        it 'accepts the password used to generate the response' do
          expect(message.password?(password, server_challenge)).to be true
        end

        it 'rejects a different non-empty password' do
          expect(message.password?('incorrect', server_challenge)).to be false
        end

        it 'recognizes only an empty password as blank' do
          expect(message.blank_password?(server_challenge)).to eq(password.empty?)
        end

        it 'rejects a different server challenge' do
          expect(message.password?(password, "\x00" * 8)).to be false
        end

        it 'accepts an integer server challenge' do
          expect(message.password?(password, type2.challenge)).to be true
        end

        it 'rejects a modified proof' do
          message.ntlm_response.setbyte(0, message.ntlm_response.getbyte(0) ^ 1)
          expect(message.password?(password, server_challenge)).to be false
        end

        it 'rejects a modified blob' do
          message.ntlm_response.setbyte(24, message.ntlm_response.getbyte(24) ^ 1)
          expect(message.password?(password, server_challenge)).to be false
        end
      end
    end
  end

  describe '#serialize' do
    subject(:message) { described_class.create(opts) }

    context 'when the username contains non-ASCI characters' do
      let(:t3) {
        t2 = Net::NTLM::Message::Type2.new
        t2.response(
          {
            user: 'Hélène',
            password: '123456',
            domain: ''
          },
          {
            ntlmv2: true,
            workstation: 'testlab.local'
          }
        )
      }

      it 'serializes without error' do
        expect { t3.serialize }.not_to raise_error
      end
    end

    context 'with the UNICODE flag set' do
      let(:opts) {
        { lm_response: "\x00".b, ntlm_response: '', domain: '', workstation: '', user: '',
       flag: Net::NTLM::DEFAULT_FLAGS[:TYPE3] | Net::NTLM::FLAGS[:UNICODE] }
      }

      it 'pads the domain field to a multiple of 2' do
        message.serialize
        expect(message[:domain][:offset].value % 2).to eq 0
      end

      it 'pads the user field to a multiple of 2' do
        message.serialize
        expect(message[:user][:offset].value % 2).to eq 0
      end

      it 'pads the workstation field to a multiple of 2' do
        message.serialize
        expect(message[:workstation][:offset].value % 2).to eq 0
      end
    end
  end
end
