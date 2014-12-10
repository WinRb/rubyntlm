require 'spec_helper'

describe Net::NTLM::Client::Session do
  let(:t2_challenge) { Net::NTLM::Message.decode64 "TlRMTVNTUAACAAAADAAMADgAAAA1goriAAyk1DmJUnUAAAAAAAAAAFAAUABEAAAABgLwIwAAAA9TAEUAUgBWAEUAUgACAAwAUwBFAFIAVgBFAFIAAQAMAFMARQBSAFYARQBSAAQADABzAGUAcgB2AGUAcgADAAwAcwBlAHIAdgBlAHIABwAIADd7mrNaB9ABAAAAAA==" }
  let(:inst) { Net::NTLM::Client::Session.new(nil, t2_challenge) }
  let(:user_session_key) {["3c4918ff0b33e2603e5d7ceaf34bb7d5"].pack("H*")}

  describe "#sign_message" do
    let(:client_sign_key) {["3c4918ff0b33e2603e5d7ceaf34bb7d5"].pack("H*")}
    let(:client_seal_key) {["51eb7030ed5875e5c33e4501d27edbac"].pack("H*")}

    it "signs a message and when KEY_EXCHANGE is true" do
      expect(inst).to receive(:client_sign_key).and_return(client_sign_key)
      expect(inst).to receive(:client_seal_key).and_return(client_seal_key)
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
