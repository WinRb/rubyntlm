# frozen_string_literal: true

module Net
  module NTLM
    # Channel binding data used for the MsvAvChannelBindings AV_PAIR.
    class ChannelBinding
      # Creates a ChannelBinding used for Extended Protection Authentication
      # @see http://blogs.msdn.com/b/openspecification/archive/2013/03/26/ntlm-and-channel-binding-hash-aka-exteneded-protection-for-authentication.aspx
      #
      # @param outer_channel [OpenSSL::X509::Certificate] Server certificate securing
      #   the outer TLS channel
      # @return [NTLM::ChannelBinding] A ChannelBinding holding a token that can be
      #   embedded in a {Type3} message
      def self.create(outer_channel)
        new(outer_channel)
      end

      # @param outer_channel [OpenSSL::X509::Certificate] Server certificate securing
      #   the outer TLS channel
      def initialize(outer_channel)
        @channel = outer_channel
        @unique_prefix = 'tls-server-end-point'
        @initiator_addtype = 0
        @initiator_address_length = 0
        @acceptor_addrtype = 0
        @acceptor_address_length = 0
      end

      attr_reader :channel, :unique_prefix, :initiator_addtype, :initiator_address_length, :acceptor_addrtype,
                  :acceptor_address_length

      # Returns a channel binding hash acceptable for use as a AV_PAIR MsvAvChannelBindings
      #   field value as specified in the NTLM protocol
      #
      # @return [String] MD5 hash of gss_channel_bindings_struct
      def channel_binding_token
        @channel_binding_token ||= OpenSSL::Digest::MD5.new(gss_channel_bindings_struct).digest
      end

      def gss_channel_bindings_struct
        @gss_channel_bindings_struct ||= begin
          token = pack_address_header
          token << [application_data.length].pack('I')
          token << application_data
          token
        end
      end

      # Returns the hash of the server certificate as defined by the
      # "tls-server-end-point" channel binding type (RFC 5929 section 4.1):
      # the digest is selected from the certificate's own signature
      # algorithm, with MD5 and SHA-1 signatures upgraded to SHA-256.
      #
      # @return [OpenSSL::Digest] digest of the DER-encoded certificate
      def channel_hash
        @channel_hash ||= channel_binding_digest.new(channel.to_der)
      end

      def application_data
        @application_data ||= begin
          data = +unique_prefix
          data << ':'
          data << channel_hash.digest
          data
        end
      end

      private

      # RFC 5929 section 4.1 selects the tls-server-end-point hash from the
      # server certificate's signature algorithm. Anything that is not an
      # explicit SHA-384 or SHA-512 signature (including MD5, SHA-1 and
      # unknown algorithms such as RSA-PSS) falls back to SHA-256.
      def channel_binding_digest
        case channel.signature_algorithm
        when /sha384/i then OpenSSL::Digest::SHA384
        when /sha512/i then OpenSSL::Digest::SHA512
        else OpenSSL::Digest::SHA256
        end
      end

      def pack_address_header
        [initiator_addtype, initiator_address_length, acceptor_addrtype, acceptor_address_length].pack('I4')
      end
    end
  end
end
