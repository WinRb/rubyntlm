# frozen_string_literal: true

module Net
  module NTLM
    class Message
      # @private false
      class Type1 < Message
        string :sign, { size: 8, value: SSP_SIGN }
        int32_le :type, { value: 1 }
        int32_le :flag, { value: DEFAULT_FLAGS[:TYPE1] }
        security_buffer :domain,       { value: '' }
        security_buffer :workstation,  { value: Socket.gethostname }
        string          :os_version,   { size: 8, value: '', active: false }
      end
    end
  end
end
