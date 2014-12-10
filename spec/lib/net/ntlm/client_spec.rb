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

    it "clears instance variables on new init_context" do
      inst.instance_variable_set :@user_session_key, "BADKEY"
      expect(inst.user_session_key).to eq("BADKEY")
      inst.init_context
      expect(inst.user_session_key).to be_nil
      expect(inst.instance_variable_get(:@username)).to eq("test")
      expect(inst.instance_variable_get(:@password)).to eq("test01")
      expect(inst.instance_variable_get(:@workstation)).to eq("testhost")
      expect(inst.instance_variable_get(:@flags)).to eq(Net::NTLM::Client::DEFAULT_FLAGS)
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

     it "returns a Type3 message" do
       t2_challenge = "TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA=="
       t3 = inst.init_context t2_challenge
       expect(t3).to be_instance_of Net::NTLM::Message::Type3
     end

  end

  describe "#sign_message" do
    let(:client_to_server_sign_key) {["3c4918ff0b33e2603e5d7ceaf34bb7d5"].pack("H*")}
    let(:client_to_server_seal_key) {["51eb7030ed5875e5c33e4501d27edbac"].pack("H*")}

    it "signs a message and when KEY_EXCHANGE is true" do
      expect(inst).to receive(:client_to_server_sign_key).and_return(client_to_server_sign_key)
      expect(inst).to receive(:client_to_server_seal_key).and_return(client_to_server_seal_key)
      expect(inst).to receive(:negotiate_key_exchange?).and_return(true)
      sm = inst.sign_message("Test Message")
      str = "\x01\x00\x00\x00\xC2\xE6\t\xFB\x05q\xC1\xC7\x00\x00\x00\x00".force_encoding(Encoding::ASCII_8BIT)
      expect(sm).to eq(str)
    end

  end

  describe "#master_key" do
    it "returns a random 16-byte key when negotiate_key_exchange? is true" do
      expect(inst).to receive(:negotiate_key_exchange?).and_return(true)
      expect(inst).not_to receive(:user_session_key)
      inst.master_key
    end

    it "returns the user_session_key when negotiate_key_exchange? is false" do
      expect(inst).to receive(:negotiate_key_exchange?).and_return(false)
      expect(inst).to receive(:user_session_key).and_return(user_session_key)
      inst.master_key
    end
  end

end
