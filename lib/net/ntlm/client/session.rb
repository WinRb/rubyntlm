# frozen_string_literal: true

require 'net/ntlm/client/session_crypto'

module Net
  module NTLM
    # An authenticated NTLM session: message signing, sealing and key exchange.
    class Client::Session
      include Client::SessionCrypto

      VERSION_MAGIC = "\x01\x00\x00\x00"
      TIME_OFFSET   = 11_644_473_600
      MAX64         = 0xffffffffffffffff
      CLIENT_TO_SERVER_SIGNING = "session key to client-to-server signing key magic constant\0"
      SERVER_TO_CLIENT_SIGNING = "session key to server-to-client signing key magic constant\0"
      CLIENT_TO_SERVER_SEALING = "session key to client-to-server sealing key magic constant\0"
      SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant\0"

      attr_reader :client, :challenge_message, :channel_binding

      # @param client [Net::NTLM::Client] the client instance
      # @param challenge_message [Net::NTLM::Message::Type2] server message
      def initialize(client, challenge_message, channel_binding = nil)
        @client = client
        @challenge_message = challenge_message
        @channel_binding = channel_binding
      end

      # Generate an NTLMv2 AUTHENTICATE_MESSAGE
      # @see http://msdn.microsoft.com/en-us/library/cc236643.aspx
      # @return [Net::NTLM::Message::Type3]
      def authenticate!
        calculate_user_session_key!
        t3 = Message::Type3.create(type3_options)
        exchange_session_key(t3) if negotiate_key_exchange?
        t3
      end

      def sign_message(message)
        seq = sequence
        sig = OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), client_sign_key, "#{seq}#{message}")[0..7]
        sig = client_cipher.encrypt sig if negotiate_key_exchange?
        "#{VERSION_MAGIC}#{sig}#{seq}"
      end

      def verify_signature(signature, message)
        seq = signature[-4..]
        sig = OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), server_sign_key, "#{seq}#{message}")[0..7]
        sig = server_cipher.encrypt sig if negotiate_key_exchange?
        "#{VERSION_MAGIC}#{sig}#{seq}" == signature
      end

      def seal_message(message)
        client_cipher.encrypt(message)
      end

      def unseal_message(emessage)
        server_cipher.encrypt(emessage)
      end

      def anonymous?
        username == '' && password == ''
      end

      alias is_anonymous? anonymous?

      private

      def type3_options
        {
          lm_response: anonymous? ? "\x00".b : lmv2_resp,
          ntlm_response: anonymous? ? '' : ntlmv2_resp,
          domain: domain,
          user: username,
          workstation: workstation,
          flag: (challenge_message.flag & client.flags)
        }
      end

      def exchange_session_key(type3)
        type3.enable(:session_key)
        rc4 = Net::NTLM::Rc4.new(user_session_key)
        type3.session_key = rc4.encrypt(exported_session_key)
      end

      def use_oem_strings?
        # @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
        !challenge_message.flag?(:UNICODE) && challenge_message.flag?(:OEM)
      end

      def negotiate_key_exchange?
        challenge_message.flag? :KEY_EXCHANGE
      end

      def username
        oem_or_unicode_str client.username
      end

      def password
        oem_or_unicode_str client.password
      end

      def workstation
        (client.workstation ? oem_or_unicode_str(client.workstation) : '')
      end

      def domain
        (client.domain ? oem_or_unicode_str(client.domain) : '')
      end

      def oem_or_unicode_str(str)
        if use_oem_strings?
          NTLM::EncodeUtil.decode_utf16le str
        else
          NTLM::EncodeUtil.encode_utf16le str
        end
      end
    end
  end
end
