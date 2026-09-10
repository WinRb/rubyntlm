# frozen_string_literal: true

module Net
  # NTLM response builders: LM, NTLM, NTLMv2, LMv2 and NTLM2 session responses.
  module NTLM
    class << self
      # Builds an LM response for the given challenge
      # @param [Hash] arg :lm_hash, :challenge
      def lm_response(arg)
        hash, chal = lm_args(arg)
        keys = gen_keys hash.ljust(21, "\0")
        apply_des(pack_challenge(chal), keys).join
      end

      # Builds an NTLM response for the given challenge
      # @param [Hash] arg :ntlm_hash, :challenge
      def ntlm_response(arg)
        hash = arg[:ntlm_hash]
        chal = arg[:challenge]
        chal = NTLM.pack_int64le(chal) if chal.is_a?(Integer)
        keys = gen_keys hash.ljust(21, "\0")
        apply_des(chal, keys).join
      end

      # Builds an NTLMv2 response for the given challenge
      # @param [Hash] arg :ntlmv2_hash, :challenge, :target_info
      # @option opt [String] :client_challenge 8-byte client challenge
      # @option opt [Integer] :timestamp Time of the response
      def ntlmv2_response(arg, opt = {})
        key, chal, ti = ntlmv2_args(arg)
        cc = client_challenge(opt)
        bb = ntlmv2_blob(ti, opt[:timestamp], cc).serialize
        OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), key, pack_challenge(chal) + bb) + bb
      end

      # Builds an LMv2 response for the given challenge
      # @param [Hash] arg :ntlmv2_hash, :challenge
      # @option opt [String] :client_challenge 8-byte client challenge
      def lmv2_response(arg, opt = {})
        key = arg[:ntlmv2_hash]
        chal = arg[:challenge]

        chal = NTLM.pack_int64le(chal) if chal.is_a?(Integer)

        cc = opt[:client_challenge] || rand(MAX64)
        cc = NTLM.pack_int64le(cc) if cc.is_a?(Integer)

        OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), key, chal + cc) + cc
      end

      # Builds an NTLM2 session response for the given challenge
      # @param [Hash] arg :ntlm_hash, :challenge
      # @option opt [String] :client_challenge 8-byte client challenge
      def ntlm2_session(arg, opt = {})
        passwd_hash, chal = ntlm2_session_args(arg)
        cc = client_challenge(opt)
        keys = gen_keys(passwd_hash.ljust(21, "\0"))
        session_hash = OpenSSL::Digest::MD5.digest(pack_challenge(chal) + cc).slice(0, 8)
        response = apply_des(session_hash, keys).join
        [cc.ljust(24, "\0"), response]
      end

      private

      # @api private
      def lm_args(arg)
        [arg[:lm_hash], arg[:challenge]]
      rescue StandardError
        raise ArgumentError
      end

      # @api private
      def ntlmv2_args(arg)
        [arg[:ntlmv2_hash], arg[:challenge], arg[:target_info]]
      rescue StandardError
        raise ArgumentError
      end

      # @api private
      def ntlm2_session_args(arg)
        [arg[:ntlm_hash], arg[:challenge]]
      rescue StandardError
        raise ArgumentError
      end

      # @api private
      def client_challenge(opt)
        cc = opt[:client_challenge] || rand(MAX64)
        cc = NTLM.pack_int64le(cc) if cc.is_a?(Integer)
        cc
      end

      # @api private
      def pack_challenge(chal)
        chal.is_a?(Integer) ? NTLM.pack_int64le(chal) : chal
      end

      # @api private
      def ntlmv2_blob(target_info, timestamp, challenge)
        ts = timestamp || Time.now.to_i
        # epoch -> milsec from Jan 1, 1601
        ts = 10_000_000 * (ts + TIME_OFFSET)

        blob = Blob.new
        blob.timestamp = ts
        blob.challenge = challenge
        blob.target_info = target_info
        blob
      end
    end
  end
end
