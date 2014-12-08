module Net
  module NTLM
    class Client

      VERSION_MAGIC = "\x01\x00\x00\x00"
      TIME_OFFSET   = 11644473600
      CLIENT_TO_SERVER_SIGNING = "session key to client-to-server signing key magic constant\0"
      SERVER_TO_CLIENT_SIGNING = "session key to server-to-client signing key magic constant\0"
      CLIENT_TO_SERVER_SEALING = "session key to client-to-server sealing key magic constant\0"
      SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant\0"
      DEFAULT_FLAGS = NTLM::FLAGS[:UNICODE] | NTLM::FLAGS[:OEM] |
        NTLM::FLAGS[:SIGN]   | NTLM::FLAGS[:SEAL]         | NTLM::FLAGS[:REQUEST_TARGET] |
        NTLM::FLAGS[:NTLM]   | NTLM::FLAGS[:ALWAYS_SIGN]  | NTLM::FLAGS[:NTLM2_KEY] |
        NTLM::FLAGS[:KEY128] | NTLM::FLAGS[:NEG_KEY_EXCH] | NTLM::FLAGS[:KEY56]

      attr_reader :flags

      def initialize(username, password, opts = {})
        @username     = username
        @password     = password
        @domain       = opts[:domain] || ""
        @workstation  = opts[:workstation] || nil
        @flags        = opts[:flags] || DEFAULT_FLAGS
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

      def user_session_key
        @user_session_key ||=  nil
      end

      def master_key
        @master_key ||= OpenSSL::Cipher.new("rc4").random_key
      end

      def sequence
        [raw_sequence].pack("V*")
      end


      private


      def type1_message
        type1 = Message::Type1.new
        type1[:flag].value = flags
        type1.domain = @domain if @domain
        type1.workstation = @workstation if @workstation
        type1
      end

      def type2_message=(message)
        @type2_message = Net::NTLM::Message.decode64(message)
      end

      def type2_message
        @type2_message
      end

      def type3_message(resp)
        self.type2_message = resp
        calculate_user_session_key!
        type3_opts = {
          lm_response:    lmv2_resp,
          ntlm_response:  ntlmv2_resp,
          domain:         @domain,
          user:           username,
          workstation:    @workstation,
          flag:           (type2_message.flag & flags)
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

      def raw_sequence
        if defined? @raw_sequence
          @raw_sequence += 1
        else
          @raw_sequence = 0
        end
      end

      def signing_key
        session_key
      end

      def client_challenge
        @client_challenge ||= Net::NTLM.pack_int64le rand(Net::NTLM::MAX64)
      end

      def server_challenge
        @server_challenge ||= type2_message[:challenge].serialize
      end

      def timestamp
        # epoch -> milsec from Jan 1, 1601
        @timestamp ||= 10000000 * (Time.now.to_i + TIME_OFFSET)
      end

      def use_oem_strings?
        type2_message.has_flag? :OEM
      end

      def username
        oem_or_unicode_str @username
      end

      def password
        oem_or_unicode_str @password
      end

      def workstation
        oem_or_unicode_str @workstation
      end

      def domain
        oem_or_unicode_str @domain
      end

      def oem_or_unicode_str(str)
        if use_oem_strings?
          NTLM::EncodeUtil.decode_utf16le str
        else
          NTLM::EncodeUtil.encode_utf16le str
        end
      end

      def ntlmv2_hash
        @ntlmv2_hash ||= NTLM.ntlmv2_hash(username, password, domain, {client_challenge: client_challenge, unicode: !use_oem_strings?})
      end

      def calculate_user_session_key!
        @user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, nt_proof_str)
      end

      def lmv2_resp
        OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, server_challenge + client_challenge) + client_challenge
      end

      def ntlmv2_resp
        nt_proof_str + blob
      end

      def nt_proof_str
        @nt_proof_str ||= OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, server_challenge + blob)
      end

      def blob
        @blob ||= begin
          b = Blob.new
          b.timestamp = timestamp
          b.challenge = client_challenge
          b.target_info = type2_message.target_info
          b.serialize
        end
      end

    end
  end
end
