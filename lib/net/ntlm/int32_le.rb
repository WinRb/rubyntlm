# frozen_string_literal: true

module Net
  module NTLM
    # 32-bit little-endian integer field.
    class Int32LE < Field
      def initialize(opt)
        super(opt)
        @size = 4
      end

      def parse(str, offset = 0)
        if @active && str.size >= offset + @size
          @value = str.slice(offset, @size).unpack1('V')
          @size
        else
          0
        end
      end

      def serialize
        [@value].pack('V') if @active
      end
    end
  end
end
