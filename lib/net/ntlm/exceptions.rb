# frozen_string_literal: true

module Net
  module NTLM
    class NtlmError < StandardError; end

    # Raised when target info AV_PAIR data cannot be parsed.
    class InvalidTargetDataError < NtlmError
      attr_reader :data

      def initialize(msg, data)
        @data = data
        super(msg)
      end
    end
  end
end
