# frozen_string_literal: true

module Net
  module NTLM
    class Client
      # Session key derivation and NTLMv2 response building for
      # {Net::NTLM::Client::Session}. Included into Session; not used directly.
      module SessionCrypto
        # @return [String] session key exchanged with (or derived for) the server
        def exported_session_key
          @exported_session_key ||=
            if negotiate_key_exchange?
              OpenSSL::Random.random_bytes(16)
            else
              user_session_key
            end
        end

        private

        def user_session_key
          @user_session_key ||= nil
        end

        def calculate_user_session_key!
          @user_session_key = if anonymous?
                                # see MS-NLMP section 3.4
                                "\x00".b * 16
                              else
                                OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), ntlmv2_hash, nt_proof_str)
                              end
        end

        def ntlmv2_hash
          @ntlmv2_hash ||= NTLM.ntlmv2_hash(username, password, domain,
                                            { client_challenge: client_challenge, unicode: !use_oem_strings? })
        end

        def lmv2_resp
          OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), ntlmv2_hash,
                               server_challenge + client_challenge) + client_challenge
        end

        def ntlmv2_resp
          nt_proof_str + blob
        end

        def nt_proof_str
          @nt_proof_str ||= OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), ntlmv2_hash, server_challenge + blob)
        end

        def blob
          @blob ||=
            begin
              b = Blob.new
              b.timestamp = timestamp
              b.challenge = client_challenge
              b.target_info = target_info
              b.serialize
            end
        end

        def target_info
          @target_info ||= if channel_binding
                             t = Net::NTLM::TargetInfo.new(challenge_message.target_info)
                             av_id = Net::NTLM::TargetInfo::MSV_AV_CHANNEL_BINDINGS
                             t.av_pairs[av_id] = channel_binding.channel_binding_token
                             t.to_s
                           else
                             challenge_message.target_info
                           end
        end

        def client_sign_key
          @client_sign_key ||= OpenSSL::Digest.digest('MD5', "#{exported_session_key}#{CLIENT_TO_SERVER_SIGNING}")
        end

        def server_sign_key
          @server_sign_key ||= OpenSSL::Digest.digest('MD5', "#{exported_session_key}#{SERVER_TO_CLIENT_SIGNING}")
        end

        def client_seal_key
          @client_seal_key ||= OpenSSL::Digest.digest('MD5', "#{exported_session_key}#{CLIENT_TO_SERVER_SEALING}")
        end

        def server_seal_key
          @server_seal_key ||= OpenSSL::Digest.digest('MD5', "#{exported_session_key}#{SERVER_TO_CLIENT_SEALING}")
        end

        def client_cipher
          @client_cipher ||= Net::NTLM::Rc4.new(client_seal_key)
        end

        def server_cipher
          @server_cipher ||= Net::NTLM::Rc4.new(server_seal_key)
        end

        def client_challenge
          @client_challenge ||= NTLM.pack_int64le(rand(MAX64))
        end

        def server_challenge
          @server_challenge ||= challenge_message[:challenge].serialize
        end

        # epoch -> milsec from Jan 1, 1601
        # @see http://support.microsoft.com/kb/188768
        def timestamp
          @timestamp ||= 10_000_000 * (Time.now.to_i + TIME_OFFSET)
        end

        def sequence
          [raw_sequence].pack('V*')
        end

        def raw_sequence
          if defined? @raw_sequence
            @raw_sequence += 1
          else
            @raw_sequence = 0
          end
        end
      end
    end
  end
end
