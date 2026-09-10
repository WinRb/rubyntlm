# frozen_string_literal: true

module Net
  module NTLM
    class Message
      # @private false
      class Type3 < Message
        string :sign, { size: 8, value: SSP_SIGN }
        int32_le :type, { value: 3 }
        security_buffer :lm_response,   { value: '' }
        security_buffer :ntlm_response, { value: '' }
        security_buffer :domain,        { value: '' }
        security_buffer :user,          { value: '' }
        security_buffer :workstation,   { value: '' }
        security_buffer :session_key,   { value: '', active: false }
        int32_le :flag, { value: 0, active: false }
        string :os_version, { size: 8, active: false }

        class << Type3
          # Builds a Type 3 packet
          # @note All options must be properly encoded with either unicode or oem encoding
          # @return [Type3]
          # @option arg [String] :lm_response The LM hash
          # @option arg [String] :ntlm_response The NTLM hash
          # @option arg [String] :domain The domain to authenticate to
          # @option arg [String] :workstation The name of the calling workstation
          # @option arg [String] :session_key The session key
          # @option arg [Integer] :flag Flags for the packet
          def create(arg, _opt = {})
            t = new
            t.lm_response = arg[:lm_response]
            t.ntlm_response = arg[:ntlm_response]
            t.domain = arg[:domain]
            t.user = arg[:user]
            t.workstation = arg[:workstation] if arg[:workstation]
            enable_session_key(t, arg)
            enable_flag(t, arg)
            t
          end

          private

          def enable_session_key(type3, arg)
            return unless arg[:session_key]

            type3.enable(:session_key)
            type3.session_key = arg[:session_key]
          end

          def enable_flag(type3, arg)
            return unless arg[:flag]

            type3.enable(:session_key)
            type3.enable(:flag)
            type3.flag = arg[:flag]
          end
        end

        # @param server_challenge (see #password?)
        def blank_password?(server_challenge)
          password?('', server_challenge)
        end

        # @param password [String]
        # @param server_challenge [String] The server's {Type2#challenge challenge} from the
        #   {Type2} message for which this object is a response.
        # @return [true] if +password+ was the password used to generate this
        #   {Type3} message
        # @return [false] otherwise
        def password?(password, server_challenge)
          case ntlm_version
          when :ntlm2_session
            ntlm2_session_password?(password, server_challenge)
          when :ntlmv2
            ntlmv2_password?(password, server_challenge)
          else
            raise
          end
        end

        # @return [Symbol]
        def ntlm_version
          if ntlm_response.size == 24 && lm_response[0, 8] != "\x00" * 8 && lm_response[8, 16] == "\x00" * 16
            :ntlm2_session
          elsif ntlm_response.size == 24
            :ntlmv1
          elsif ntlm_response.size > 24
            :ntlmv2
          end
        end

        private

        def ntlm2_session_password?(password, server_challenge)
          ntlm_response == ntlm2_session_empty_hash(password, server_challenge)
        end

        def ntlm2_session_empty_hash(password, server_challenge)
          NTLM.ntlm2_session(
            { ntlm_hash: NTLM.ntlm_hash(password), challenge: server_challenge },
            { client_challenge: lm_response[0, 8] }
          ).last
        end

        def ntlmv2_password?(password, server_challenge)
          # user and domain are already UTF-16LE from the wire; encode the
          # supplied password to match before deriving the verification key.
          key = NTLM.ntlmv2_hash(user, EncodeUtil.encode_utf16le(password), domain, unicode: true)
          server_challenge = NTLM.pack_int64le(server_challenge) if server_challenge.is_a?(Integer)

          # Authenticate the exact blob bytes. Rebuilding the blob truncates
          # sub-second timestamps and rejects otherwise valid responses.
          expected_proof = OpenSSL::HMAC.digest(
            OpenSSL::Digest.new('MD5'), key, server_challenge + ntlm_response[16..]
          )
          expected_proof == ntlm_response[0, 16]
        end
      end
    end
  end
end
