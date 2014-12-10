require 'spec_helper'

describe Net::NTLM::Client do
  let(:inst) { Net::NTLM::Client.new("test", "test01", workstation: "testhost") }
  let(:user_session_key) {["3c4918ff0b33e2603e5d7ceaf34bb7d5"].pack("H*")}

  describe "#init_context" do

    it "returns a default Type1 message" do
      t2 = inst.init_context
      expect(t2).to be_instance_of Net::NTLM::Message::Type1
      expect(t2.domain).to eq("")
      expect(t2.workstation).to eq("testhost")
      expect(t2.has_flag?(:UNICODE)).to be true
      expect(t2.has_flag?(:OEM)).to be true
      expect(t2.has_flag?(:SIGN)).to be true
      expect(t2.has_flag?(:SEAL)).to be true
      expect(t2.has_flag?(:REQUEST_TARGET)).to be true
      expect(t2.has_flag?(:NTLM)).to be true
      expect(t2.has_flag?(:ALWAYS_SIGN)).to be true
      expect(t2.has_flag?(:NTLM2_KEY)).to be true
      expect(t2.has_flag?(:KEY128)).to be true
      expect(t2.has_flag?(:KEY_EXCHANGE)).to be true
      expect(t2.has_flag?(:KEY56)).to be true
    end

    it "clears session variable on new init_context" do
      inst.instance_variable_set :@session, "BADSESSION"
      expect(inst.session).to eq("BADSESSION")
      inst.init_context
      expect(inst.session).to be_nil
    end

    it "returns a Type1 message with custom flags" do
      flags = Net::NTLM::FLAGS[:UNICODE] | Net::NTLM::FLAGS[:REQUEST_TARGET] | Net::NTLM::FLAGS[:NTLM]
      inst = Net::NTLM::Client.new("test", "test01", workstation: "testhost", flags: flags)
      t2 = inst.init_context
      expect(t2).to be_instance_of Net::NTLM::Message::Type1
      expect(t2.domain).to eq("")
      expect(t2.workstation).to eq("testhost")
      expect(t2.has_flag?(:UNICODE)).to be true
      expect(t2.has_flag?(:OEM)).to be false
      expect(t2.has_flag?(:SIGN)).to be false
      expect(t2.has_flag?(:SEAL)).to be false
      expect(t2.has_flag?(:REQUEST_TARGET)).to be true
      expect(t2.has_flag?(:NTLM)).to be true
      expect(t2.has_flag?(:ALWAYS_SIGN)).to be false
      expect(t2.has_flag?(:NTLM2_KEY)).to be false
      expect(t2.has_flag?(:KEY128)).to be false
      expect(t2.has_flag?(:KEY_EXCHANGE)).to be false
      expect(t2.has_flag?(:KEY56)).to be false
    end

    it "calls authenticate! when we receive a Challenge Message" do
      t2_challenge = "TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA=="
      session = double("session")
      expect(session).to receive(:authenticate!)
      expect(Net::NTLM::Client::Session).to receive(:new).with(inst, instance_of(Net::NTLM::Message::Type2)).and_return(session)
      inst.init_context t2_challenge
    end

  end

end
