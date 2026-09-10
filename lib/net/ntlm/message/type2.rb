# frozen_string_literal: true

module Net
  module NTLM
    class Message
      # @private false
      class Type2 < Message
        string :sign, { size: 8, value: SSP_SIGN }
        int32_le :type, { value: 2 }
        security_buffer :target_name, { size: 0, value: '' }
        int32_le         :flag,        { value: DEFAULT_FLAGS[:TYPE2] }
        int64_le         :challenge,   { value: 0 }
        int64_le         :context,     { value: 0, active: false }
        security_buffer :target_info, { value: '', active: false }
        string          :os_version,  { size: 8, value: '', active: false }

        # Generates a Type 3 response based on the Type 2 Information
        # @return [Type3]
        # @option arg [String] :username The username to authenticate with
        # @option arg [String] :password The user's password
        # @option arg [String] :domain ('') The domain to authenticate to
        # @option opt [String] :workstation (Socket.gethostname) The name of the calling workstation
        # @option opt [Boolean] :use_default_target (false) Use the domain supplied by the server in the Type 2 packet
        # @note An empty :domain option authenticates to the local machine.
        # @note The :use_default_target has precedence over the :domain option
        def response(arg, opt = {})
          creds = response_credentials(arg, opt)
          normalize_response_encoding(creds, opt)
          creds[:domain] = target_name if opt[:use_default_target]
          lm_res, ntlm_res = build_responses(creds, opt)
          build_type3(creds, lm_res, ntlm_res)
        end

        private

        def response_credentials(arg, opt)
          usr = arg[:user]
          pwd = arg[:password]
          raise ArgumentError, 'user and password have to be supplied' if usr.nil? || pwd.nil?

          build_credentials(usr, pwd, arg, opt)
        end

        def build_credentials(usr, pwd, arg, opt)
          {
            user: usr,
            password: pwd,
            domain: arg[:domain] ? arg[:domain].upcase : '',
            workstation: opt[:workstation] || Socket.gethostname,
            client_challenge: normalize_client_challenge(opt)
          }
        end

        def normalize_client_challenge(opt)
          cc = opt[:client_challenge] || rand(MAX64)
          cc = NTLM.pack_int64le(cc) if cc.is_a?(Integer)
          opt[:client_challenge] = cc
        end

        def normalize_response_encoding(creds, opt)
          decode_response_strings(creds, opt) if flag?(:OEM) && opt[:unicode]
          encode_response_strings(creds, opt) if flag?(:UNICODE) && !opt[:unicode]
        end

        def decode_response_strings(creds, opt)
          creds[:user] = NTLM::EncodeUtil.decode_utf16le(creds[:user])
          creds[:password] = NTLM::EncodeUtil.decode_utf16le(creds[:password])
          creds[:workstation] = NTLM::EncodeUtil.decode_utf16le(creds[:workstation])
          creds[:domain] = NTLM::EncodeUtil.decode_utf16le(creds[:domain])
          opt[:unicode] = false
        end

        def encode_response_strings(creds, opt)
          creds[:user] = NTLM::EncodeUtil.encode_utf16le(creds[:user])
          creds[:password] = NTLM::EncodeUtil.encode_utf16le(creds[:password])
          creds[:workstation] = NTLM::EncodeUtil.encode_utf16le(creds[:workstation])
          creds[:domain] = NTLM::EncodeUtil.encode_utf16le(creds[:domain])
          opt[:unicode] = true
        end

        def build_responses(creds, opt)
          challenge = self[:challenge].serialize
          if opt[:ntlmv2]
            ntlmv2_responses(creds, challenge, opt)
          elsif flag?(:NTLM2_KEY)
            ntlm2_session_responses(creds, challenge, opt)
          else
            v1_responses(creds, challenge, opt)
          end
        end

        def ntlmv2_responses(creds, challenge, opt)
          ar = { ntlmv2_hash: NTLM.ntlmv2_hash(creds[:user], creds[:password], creds[:domain], opt),
                 challenge: challenge, target_info: target_info }
          [NTLM.lmv2_response(ar, opt), NTLM.ntlmv2_response(ar, opt)]
        end

        def ntlm2_session_responses(creds, challenge, opt)
          ar = { ntlm_hash: NTLM.ntlm_hash(creds[:password], opt), challenge: challenge }
          NTLM.ntlm2_session(ar, opt)
        end

        def v1_responses(creds, challenge, opt)
          lm_res = NTLM.lm_response({ lm_hash: NTLM.lm_hash(creds[:password]), challenge: challenge })
          ntlm_res = NTLM.ntlm_response({ ntlm_hash: NTLM.ntlm_hash(creds[:password], opt), challenge: challenge })
          [lm_res, ntlm_res]
        end

        def build_type3(creds, lm_res, ntlm_res)
          Type3.create({
            lm_response: lm_res,
            ntlm_response: ntlm_res,
            domain: creds[:domain],
            user: creds[:user],
            workstation: creds[:workstation],
            flag: flag
          })
        end
      end
    end
  end
end
