require 'spec_helper'

describe Net::NTLM::Message::Type1 do
  fields = [
      { :name => :sign, :class => Net::NTLM::String, :value => Net::NTLM::SSP_SIGN, :active => true },
      { :name => :type, :class => Net::NTLM::Int32LE, :value => 1, :active => true },
      { :name => :flag, :class => Net::NTLM::Int32LE, :value =>  Net::NTLM::DEFAULT_FLAGS[:TYPE1], :active => true },
      { :name => :domain, :class => Net::NTLM::SecurityBuffer, :value => '', :active => true },
      { :name => :workstation, :class => Net::NTLM::SecurityBuffer, :value =>  Socket.gethostname, :active => true },
      { :name => :padding, :class => Net::NTLM::String, :value => '', :active => false },
  ]
  flags = [
      :UNICODE,
      :OEM,
      :REQUEST_TARGET,
      :NTLM,
      :ALWAYS_SIGN,
      :NTLM2_KEY
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

  let(:type1_packet) {"TlRMTVNTUAABAAAAB4IIAAAAAAAgAAAAAAAAACAAAAA="}

  it 'should deserialize' do
    t1 =  Net::NTLM::Message.decode64(type1_packet)
    t1.class.should == Net::NTLM::Message::Type1
    t1.domain.should == ''
    t1.flag.should == 557575
    t1.padding.should == ''
    t1.sign.should  == "NTLMSSP\0"
    t1.type.should == 1
    t1.workstation.should == ''
  end

  it 'should serialize' do
    t1 = Net::NTLM::Message::Type1.new
    t1.workstation = ''
    t1.encode64.should == type1_packet
  end


  describe '.parse' do
    subject(:message) { described_class.parse(data) }
    # http://davenport.sourceforge.net/ntlm.html#appendixC7
    context 'NTLM2 Session Response Authentication; NTLM2 Signing and Sealing Using the 128-bit NTLM2 Session Response User Session Key With Key Exchange Negotiated' do
      let(:data) do
        ['4e544c4d5353500001000000b78208e000000000000000000000000000000000'].pack('H*')
      end

      it 'should set the magic' do
        message.sign.should eql(Net::NTLM::SSP_SIGN)
      end
      it 'should set the type' do
        message.type.should == 1
      end
      it 'should set the flags' do
        message.flag.should == 0xe00882b7
        message.should have_flag(:UNICODE)
        message.should have_flag(:OEM)
        message.should have_flag(:REQUEST_TARGET)
        message.should have_flag(:SIGN)
        message.should have_flag(:SEAL)
        message.should have_flag(:NTLM)
        message.should have_flag(:ALWAYS_SIGN)
        message.should have_flag(:NTLM2_KEY)
        message.should have_flag(:KEY128)
        message.should have_flag(:KEY_EXCHANGE)
        message.should have_flag(:KEY56)
      end
      it 'should have empty workstation' do
        message.workstation.should be_empty
      end
      it 'should have empty domain' do
        message.domain.should be_empty
      end

    end

    # http://davenport.sourceforge.net/ntlm.html#appendixC9
    context 'NTLMv2 Authentication; NTLM1 Signing and Sealing Using the 40-bit NTLMv2 User Session Key' do
      let(:data) { ['4e544c4d53535000010000003782000000000000000000000000000000000000'].pack('H*') }

      it 'should set the magic' do
        message.sign.should eql(Net::NTLM::SSP_SIGN)
      end
      it 'should set the type' do
        message.type.should == 1
      end
      it 'should set the flags' do
        message.flag.should == 0x00008237
        message.should have_flag(:UNICODE)
        message.should have_flag(:OEM)
        message.should have_flag(:REQUEST_TARGET)
        message.should have_flag(:SIGN)
        message.should have_flag(:SEAL)
        message.should have_flag(:NTLM)
        message.should have_flag(:ALWAYS_SIGN)
      end
      it 'should have empty workstation' do
        message.workstation.should be_empty
      end
      it 'should have empty domain' do
        message.domain.should be_empty
      end
    end

  end

end
