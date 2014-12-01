module Net
  module NTLM
    class Client

      VERSION_MAGIC = "\x01\x00\x00\x00"
      TIME_OFFSET   = 11644473600
      CLIENT_TO_SERVER_SIGNING = "session key to client-to-server signing key magic constant\0"
      SERVER_TO_CLIENT_SIGNING = "session key to server-to-client signing key magic constant\0"
      CLIENT_TO_SERVER_SEALING = "session key to client-to-server sealing key magic constant\0"
      SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant\0"

      attr_reader :tokens

      def initialize(user, pass, opts = {})
        @user         = user
        @pass         = pass
        @domain       = ""
        @workstation  = Socket.gethostname
        @tokens = {t1: nil, t2: nil, t3: nil}
        @user_session_key = nil
      end

      def init_context(resp = nil)
        if resp.nil?
          type1_message
        else
          type3_message resp
        end
      end

      def sign_message(message)
        seq = self.sequence
        presig = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, client_to_server_sign_key, "#{seq}#{message}")
        enc = client_cipher.update presig[0..7]
        enc << client_cipher.final
        "#{VERSION_MAGIC}#{enc}#{seq}"
      end

      def seal_message(message)
        emessage = client_cipher.update(message)
        emessage + client_cipher.final
      end

      def unseal_message(emessage)
        message = server_cipher.update(emessage)
        message + server_cipher.final
      end

      def verify_signature(signature, message)
        seq = signature[-4..-1]
        presig = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, server_to_client_sign_key, "#{seq}#{message}")
        enc = server_cipher.update presig[0..7]
        enc << server_cipher.final
        "#{VERSION_MAGIC}#{enc}#{seq}" == signature
      end

      def client_cipher
        @client_cipher ||= begin
          rc4 = OpenSSL::Cipher::Cipher.new("rc4")
          rc4.encrypt
          rc4.key = client_to_server_seal_key
          rc4
        end
      end

      def server_cipher
        @server_cipher ||= begin
          rc4 = OpenSSL::Cipher::Cipher.new("rc4")
          rc4.decrypt
          rc4.key = server_to_client_seal_key
          rc4
        end
      end

      def user_session_key
        @user_session_key
      end

      def master_key
        @master_key ||= OpenSSL::Cipher.new("rc4").random_key
      end

      def sequence
        [raw_sequence].pack("V*")
      end

      def client_to_server_sign_key
        @client_to_server_sign_key ||= begin
          OpenSSL::Digest::MD5.digest "#{master_key}#{CLIENT_TO_SERVER_SIGNING}"
        end
      end

      def server_to_client_sign_key
        @server_to_client_sign_key ||= begin
          OpenSSL::Digest::MD5.digest "#{master_key}#{SERVER_TO_CLIENT_SIGNING}"
        end
      end

      def client_to_server_seal_key
        @client_to_server_seal_key ||= begin
          OpenSSL::Digest::MD5.digest "#{master_key}#{CLIENT_TO_SERVER_SEALING}"
        end
      end

      def server_to_client_seal_key
        @server_to_client_seal_key ||= begin
          OpenSSL::Digest::MD5.digest "#{master_key}#{SERVER_TO_CLIENT_SEALING}"
        end
      end


      private


      def raw_sequence
        if defined? @raw_sequence
          @raw_sequence += 1
        else
          @raw_sequence = 0
        end
      end

      def type1_message
        type1 = Message::Type1.new
        type1[:flag].value = Net::NTLM::FLAGS[:UNICODE] | Net::NTLM::FLAGS[:OEM] |
          Net::NTLM::FLAGS[:SIGN] | Net::NTLM::FLAGS[:SEAL] |
          Net::NTLM::FLAGS[:REQUEST_TARGET] | Net::NTLM::FLAGS[:NTLM] |
          Net::NTLM::FLAGS[:ALWAYS_SIGN] | Net::NTLM::FLAGS[:NTLM2_KEY] |
          Net::NTLM::FLAGS[:KEY128] | Net::NTLM::FLAGS[:NEG_KEY_EXCH] | Net::NTLM::FLAGS[:KEY56]
        type1
      end

      def type3_message(resp)
        response Net::NTLM::Message.decode64(resp)
      end

      def signing_key
        session_key
      end

      def client_challenge
        @client_challenge ||= Net::NTLM::pack_int64le rand(Net::NTLM::MAX64)
      end

      def timestamp
        # epoch -> milsec from Jan 1, 1601
        @timestamp ||= 10000000 * (Time.now.to_i + TIME_OFFSET)
      end

      def response(type2)
        opt = {client_challenge: client_challenge}

        if type2.has_flag?(:OEM)
          user        = NTLM::EncodeUtil.decode_utf16le(@user)
          pass        = NTLM::EncodeUtil.decode_utf16le(@pass)
          @pass       = nil
          workstation = NTLM::EncodeUtil.decode_utf16le(@workstation)
          domain      = NTLM::EncodeUtil.decode_utf16le(@domain)
          opt[:unicode] = false
        else
          user        = NTLM::EncodeUtil.encode_utf16le(@user)
          pass        = NTLM::EncodeUtil.encode_utf16le(@pass)
          @pass       = nil
          workstation = NTLM::EncodeUtil.encode_utf16le(@workstation)
          domain      = NTLM::EncodeUtil.encode_utf16le(@domain)
          opt[:unicode] = true
        end

        target_info = type2.target_info
        challenge   = type2[:challenge].serialize

        @ntlmv2_hash = NTLM::ntlmv2_hash(user, pass, domain, opt)

        blob = pack_the_blob timestamp, client_challenge, target_info

        calculate_user_session_key blob, challenge

        ar = {
          :ntlmv2_hash      => @ntlmv2_hash,
          :challenge        => challenge,
          :target_info      => target_info,
          :timestamp        => timestamp,
          :client_challenge => client_challenge,
          :blob             => blob
        }

        type3_opts = {
          lm_response:    NTLM::lmv2_response(ar, opt),
          ntlm_response:  NTLM::ntlmv2_response(ar, opt),
          domain:         domain,
          user:           user,
          workstation:    workstation,
          flag:           type2.flag
        }
        t3 = Message::Type3.create type3_opts

        t3.enable(:session_key)

        rc4 = OpenSSL::Cipher::Cipher.new("rc4")
        rc4.encrypt
        rc4.key = user_session_key
        sk = rc4.update master_key
        sk << rc4.final
        t3.session_key = sk
        t3
      end

      def calculate_user_session_key(blob, challenge)
        key = @ntlmv2_hash
        tkey = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, challenge + blob)
        @user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, tkey)
      end

      def pack_the_blob(timestamp, client_challenge, target_info)
        blob = Blob.new
        blob.timestamp = timestamp
        blob.challenge = client_challenge
        blob.target_info = target_info
        blob.serialize
      end

    end
  end
end
