module Net
  module NTLM
    class Client

      VERSION_MAGIC = "\x01\x00\x00\x00"

      attr_reader :tokens

      def initialize(user, pass, opts = {})
        @user         = user
        @pass         = pass
        @domain       = ""
        @workstation  = Socket.gethostname
        @tokens = {t1: nil, t2: nil, t3: nil}
        @ntlmv2_user_session_key = nil
      end

      def init_context(base64_resp = nil)
        if base64_resp.nil?
          type1_message
        else
          type3_message base64_resp
        end
      end

      def sign_message(message, sequence: self.sequence)
        presig = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, sign_key, "#{sequence}#{message}")
        "#{VERSION_MAGIC}#{presig}#{sequence}"
      end

      def seal_message(message)
        seq = sequence
        emessage = cipher.update(message)
        emessage << cipher.final
        signature = sign_message message, sequence: seq
        "#{emessage}#{signature}"
      end

      def cipher
        @cipher ||= begin
          rc4 = OpenSSL::Cipher::Cipher.new("rc4")
          rc4.encrypt
          rc4.key = ntlmv2_user_session_key
        end
      end


      private


      def sequence
        [raw_sequence].pack("V*")
      end

      def raw_sequence
        if defined? @raw_sequence
          @raw_sequence += 1
        else
          @raw_sequence = 0
        end
      end

      def type1_message
        Message::Type1.new
      end

      def type3_message(base64_resp)
        response Net::NTLM::Message.decode64(base64_resp)
      end

      def ntlmv2_user_session_key
        @ntlmv2_user_session_key
      end

      def signing_key
        ntlmv2_user_session_key
      end

      def client_challenge
        @client_challenge ||= Net::NTLM::pack_int64le rand(Net::NTLM::MAX64)
      end

      def timestamp
        @timestamp ||= Time.now.to_i
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

        blob = NTLM.ntlmv2_response_blob(timestamp, client_challenge, target_info)
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
        Message::Type3.create type3_opts
      end

      def calculate_user_session_key(blob, challenge)
        key = @ntlmv2_hash
        tkey = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, challenge + blob)
        @ntlmv2_user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, tkey)
      end

    end
  end
end
