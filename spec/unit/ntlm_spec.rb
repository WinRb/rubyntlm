# encoding: UTF-8
$:.unshift(File.expand_path(File.dirname(__FILE__) << '../lib'))

describe Net::NTLM::Message do
  let(:type1_packet) {"TlRMTVNTUAABAAAAB4IIAAAAAAAgAAAAAAAAACAAAAA="}
  let(:type2_packet) {"TlRMTVNTUAACAAAAHAAcADgAAAAFgooCJ+UA1//+ZM4AAAAAAAAAAJAAkABUAAAABgGxHQAAAA9WAEEARwBSAEEATgBUAC0AMgAwADAAOABSADIAAgAcAFYAQQBHAFIAQQBOAFQALQAyADAAMAA4AFIAMgABABwAVgBBAEcAUgBBAE4AVAAtADIAMAAwADgAUgAyAAQAHAB2AGEAZwByAGEAbgB0AC0AMgAwADAAOABSADIAAwAcAHYAYQBnAHIAYQBuAHQALQAyADAAMAA4AFIAMgAHAAgAZBMdFHQnzgEAAAAA"}
  let(:type3_packet) {"TlRMTVNTUAADAAAAGAAYAEQAAADAAMAAXAAAAAAAAAAcAQAADgAOABwBAAAUABQAKgEAAAAAAAA+AQAABYKKAgAAAADVS27TfQGmWxSSbXmolTUQyxJmD8ISQuBKKHFKC8GksUZISYc8Ps9RAQEAAAAAAAAANasTdCfOAcsSZg/CEkLgAAAAAAIAHABWAEEARwBSAEEATgBUAC0AMgAwADAAOABSADIAAQAcAFYAQQBHAFIAQQBOAFQALQAyADAAMAA4AFIAMgAEABwAdgBhAGcAcgBhAG4AdAAtADIAMAAwADgAUgAyAAMAHAB2AGEAZwByAGEAbgB0AC0AMgAwADAAOABSADIABwAIAGQTHRR0J84BAAAAAAAAAAB2AGEAZwByAGEAbgB0AGsAbwBiAGUALgBsAG8AYwBhAGwA"}
  describe Net::NTLM::Message::Type1 do
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
  end

  describe Net::NTLM::Message::Type2 do
    it 'should deserialize' do
      t2 =  Net::NTLM::Message.decode64(type2_packet)
      t2.class.should == Net::NTLM::Message::Type2
      t2.challenge.should == 14872292244261496103
      t2.context.should == 0
      t2.flag.should == 42631685
      if "".respond_to?(:force_encoding)
        t2.padding.should == ("\x06\x01\xB1\x1D\0\0\0\x0F".force_encoding('ASCII-8BIT'))
      end
      t2.sign.should == "NTLMSSP\0"

      t2_target_info = Net::NTLM::EncodeUtil.decode_utf16le(t2.target_info)
      if RUBY_VERSION == "1.8.7"
        t2_target_info.should == "\x02\x1CVAGRANT-2008R2\x01\x1CVAGRANT-2008R2\x04\x1Cvagrant-2008R2\x03\x1Cvagrant-2008R2\a\b\e$(D+&\e(B\0\0"
      else
        t2_target_info.should == "\u0002\u001CVAGRANT-2008R2\u0001\u001CVAGRANT-2008R2\u0004\u001Cvagrant-2008R2\u0003\u001Cvagrant-2008R2\a\b፤ᐝ❴ǎ\0\0"
      end

      Net::NTLM::EncodeUtil.decode_utf16le(t2.target_name).should == "VAGRANT-2008R2"
      t2.type.should == 2
    end

    it 'should serialize' do
      source = Net::NTLM::Message.decode64(type2_packet)

      t2 =  Net::NTLM::Message::Type2.new
      t2.challenge = source.challenge
      t2.context = source.context
      t2.flag = source.flag
      t2.padding = source.padding
      t2.sign = source.sign
      t2.target_info = source.target_info
      t2.target_name = source.target_name
      t2.type = source.type
      t2.enable(:context)
      t2.enable(:target_info)
      t2.enable(:padding)

      t2.encode64.should == type2_packet
    end

    it 'should generate a type 3 response' do
      t2 = Net::NTLM::Message.decode64(type2_packet)

      type3_known = Net::NTLM::Message.decode64(type3_packet)
      type3_known.flag = 0x028a8205
      type3_known.enable(:session_key)
      type3_known.enable(:flag)

      t3 = t2.response({:user => 'vagrant', :password => 'vagrant', :domain => ''}, {:ntlmv2 => true, :workstation => 'kobe.local'})
      t3.domain.should == type3_known.domain
      t3.flag.should == type3_known.flag
      t3.sign.should == "NTLMSSP\0"
      t3.workstation.should == "k\0o\0b\0e\0.\0l\0o\0c\0a\0l\0"
      t3.user.should == "v\0a\0g\0r\0a\0n\0t\0"
      t3.session_key.should == ''
    end
  end
end


describe Net::NTLM do
  let(:passwd) {"SecREt01"}
  let(:user) {"user"}
  let(:domain) {"domain"}
  let(:challenge) {["0123456789abcdef"].pack("H*")}
  let(:client_ch) {["ffffff0011223344"].pack("H*")}
  let(:timestamp) {1055844000}
  let(:trgt_info) {[
      "02000c0044004f004d00410049004e00" +
      "01000c00530045005200560045005200" +
      "0400140064006f006d00610069006e00" +
      "2e0063006f006d000300220073006500" +
      "72007600650072002e0064006f006d00" +
      "610069006e002e0063006f006d000000" +
      "0000"
     ].pack("H*")}

  it 'should generate an lm_hash' do
    Net::NTLM::lm_hash(passwd).should == ["ff3750bcc2b22412c2265b23734e0dac"].pack("H*")
  end

  it 'should generate an ntlm_hash' do
     Net::NTLM::ntlm_hash(passwd).should == ["cd06ca7c7e10c99b1d33b7485a2ed808"].pack("H*")
  end

  it 'should generate an ntlmv2_hash' do
    Net::NTLM::ntlmv2_hash(user, passwd, domain).should == ["04b8e0ba74289cc540826bab1dee63ae"].pack("H*")
  end

  it 'should generate an lm_response' do
    Net::NTLM::lm_response(
      {
        :lm_hash => Net::NTLM::lm_hash(passwd),
        :challenge => challenge
      }
    ).should == ["c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56"].pack("H*")
  end

  it 'should generate an ntlm_response' do
    ntlm_hash = Net::NTLM::ntlm_hash(passwd)
    Net::NTLM::ntlm_response(
      {
        :ntlm_hash => ntlm_hash,
        :challenge => challenge
      }
    ).should == ["25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6"].pack("H*")
  end

  it 'should generate a lvm2_response' do
    Net::NTLM::lmv2_response(
      {
        :ntlmv2_hash => Net::NTLM::ntlmv2_hash(user, passwd, domain),
        :challenge => challenge
      },
      { :client_challenge => client_ch }
    ).should == ["d6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344"].pack("H*")
  end

  it 'should generate a ntlmv2_response' do
    Net::NTLM::ntlmv2_response(
      {
        :ntlmv2_hash => Net::NTLM::ntlmv2_hash(user, passwd, domain),
        :challenge => challenge,
        :target_info => trgt_info
      },
      {
        :timestamp => timestamp,
        :client_challenge => client_ch
      }
    ).should == [
      "cbabbca713eb795d04c97abc01ee4983" +
        "01010000000000000090d336b734c301" +
        "ffffff00112233440000000002000c00" +
      "44004f004d00410049004e0001000c00" +
        "53004500520056004500520004001400" +
        "64006f006d00610069006e002e006300" +
        "6f006d00030022007300650072007600" +
        "650072002e0064006f006d0061006900" +
        "6e002e0063006f006d00000000000000" +
        "0000"
      ].pack("H*")
  end

  it 'should generate a ntlm2_session' do
    session = Net::NTLM::ntlm2_session(
      {
        :ntlm_hash => Net::NTLM::ntlm_hash(passwd),
        :challenge => challenge
      },
      { :client_challenge => client_ch }
    )
    session[0].should == ["ffffff001122334400000000000000000000000000000000"].pack("H*")
    session[1].should == ["10d550832d12b2ccb79d5ad1f4eed3df82aca4c3681dd455"].pack("H*")
  end
end
