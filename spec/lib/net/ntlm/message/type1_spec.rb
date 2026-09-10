# frozen_string_literal: true

RSpec.describe Net::NTLM::Message::Type1 do
  fields = [
    { name: :sign, class: Net::NTLM::String, value: Net::NTLM::SSP_SIGN, active: true },
    { name: :type, class: Net::NTLM::Int32LE, value: 1, active: true },
    { name: :flag, class: Net::NTLM::Int32LE, value: Net::NTLM::DEFAULT_FLAGS[:TYPE1], active: true },
    { name: :domain, class: Net::NTLM::SecurityBuffer, value: '', active: true },
    { name: :workstation, class: Net::NTLM::SecurityBuffer, value: Socket.gethostname, active: true },
    { name: :os_version, class: Net::NTLM::String, value: '', active: false }
  ]
  flags = %i[
    UNICODE
    OEM
    REQUEST_TARGET
    NTLM
    ALWAYS_SIGN
    NTLM2_KEY
  ]
  let(:type1_packet) { 'TlRMTVNTUAABAAAAB4IIAAAAAAAgAAAAAAAAACAAAAA=' }
  let(:deserialized) { Net::NTLM::Message.decode64(type1_packet) }

  # Verifies the parsed flag integer and each expected flag name.
  def expect_flags(message, value, flags)
    aggregate_failures do
      expect(message.flag).to eq(value)
      flags.each { |flag| expect(message).to have_flag(flag) }
    end
  end

  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

  it 'deserializes the message type' do
    expect(deserialized.class).to eq(described_class)
  end

  it 'deserializes the header fields' do
    aggregate_failures do
      expect(deserialized.sign).to eq("NTLMSSP\0")
      expect(deserialized.type).to eq(1)
      expect(deserialized.flag).to eq(557_575)
    end
  end

  it 'deserializes the payload fields' do
    aggregate_failures do
      expect(deserialized.domain).to eq('')
      expect(deserialized.workstation).to eq('')
      expect(deserialized.os_version).to eq('')
    end
  end

  it 'serializes' do
    t1 = described_class.new
    t1.workstation = ''
    expect(t1.encode64).to eq(type1_packet)
  end

  describe '.parse' do
    subject(:message) { described_class.parse(data) }

    # http://davenport.sourceforge.net/ntlm.html#appendixC7
    context 'NTLM2 Session Response Authentication; NTLM2 Signing and Sealing Using the 128-bit NTLM2 Session Re' \
        'sponse User Session Key With Key Exchange Negotiated' do
      let(:data) do
        ['4e544c4d5353500001000000b78208e000000000000000000000000000000000'].pack('H*')
      end

      it 'sets the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end

      it 'sets the type' do
        expect(message.type).to eq(1)
      end

      it 'sets the flags' do
        expected_flags = %i[UNICODE OEM REQUEST_TARGET SIGN SEAL NTLM ALWAYS_SIGN NTLM2_KEY KEY128 KEY_EXCHANGE KEY56]
        expect_flags(message, 0xe00882b7, expected_flags)
      end

      it 'has empty workstation' do
        expect(message.workstation).to be_empty
      end

      it 'has empty domain' do
        expect(message.domain).to be_empty
      end
    end

    # http://davenport.sourceforge.net/ntlm.html#appendixC9
    context 'NTLMv2 Authentication; NTLM1 Signing and Sealing Using the 40-bit NTLMv2 User Session Key' do
      let(:data) { ['4e544c4d53535000010000003782000000000000000000000000000000000000'].pack('H*') }

      it 'sets the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end

      it 'sets the type' do
        expect(message.type).to eq(1)
      end

      it 'sets the flags' do
        expected_flags = %i[UNICODE OEM REQUEST_TARGET SIGN SEAL NTLM ALWAYS_SIGN]
        expect_flags(message, 0x00008237, expected_flags)
      end

      it 'has empty workstation' do
        expect(message.workstation).to be_empty
      end

      it 'has empty domain' do
        expect(message.domain).to be_empty
      end
    end

    context 'NTLMv2 with OS version' do
      let(:data) { ['4e544c4d5353500001000000978208e2000000000000000000000000000000000602f0230000000f'].pack('H*') }

      it 'sets the magic' do
        expect(message.sign).to eql(Net::NTLM::SSP_SIGN)
      end

      it 'sets the type' do
        expect(message.type).to eq(1)
      end

      it 'has empty workstation' do
        expect(message.workstation).to be_empty
      end

      it 'has empty domain' do
        expect(message.domain).to be_empty
      end

      it 'sets OS version info' do
        expect(message.os_version).to eq(['0602f0230000000f'].pack('H*'))
      end
    end
  end
end
