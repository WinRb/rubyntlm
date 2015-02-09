module Net
  module NTLM
    class Client

      DEFAULT_FLAGS = NTLM::FLAGS[:UNICODE] | NTLM::FLAGS[:OEM] |
        NTLM::FLAGS[:SIGN]   | NTLM::FLAGS[:SEAL]         | NTLM::FLAGS[:REQUEST_TARGET] |
        NTLM::FLAGS[:NTLM]   | NTLM::FLAGS[:ALWAYS_SIGN]  | NTLM::FLAGS[:NTLM2_KEY] |
        NTLM::FLAGS[:KEY128] | NTLM::FLAGS[:KEY_EXCHANGE] | NTLM::FLAGS[:KEY56]

      attr_reader :username, :password, :domain, :workstation, :flags

      # @note All string parameters should be encoded in UTF-8. The proper
      #   final encoding for placing in the various {Message}s will be chosen
      #   based on negotiation with the server.
      def initialize(username, password, opts = {})
        @username     = username
        @password     = password
        @domain       = opts[:domain] || nil
        @workstation  = opts[:workstation] || nil
        @flags        = opts[:flags] || DEFAULT_FLAGS
      end

      def init_context(resp = nil)
        if resp.nil?
          @session = nil
          type1_message
        else
          @session = Client::Session.new(self, Net::NTLM::Message.decode64(resp))
          @session.authenticate!
        end
      end

      def session
        @session
      end


      private


      def type1_message
        type1 = Message::Type1.new
        type1[:flag].value = flags
        type1.domain = domain if domain
        type1.workstation = workstation if workstation
        type1
      end

    end
  end
end

require "net/ntlm/client/session"
