# frozen_string_literal: true

module Net
  module NTLM
    # 16-bit little-endian integer field.
    class Int16LE < Field
      def initialize(opt)
        super(opt)
        @size = 2
      end

      def parse(str, offset = 0)
        if @active && str.size >= offset + @size
          @value = str[offset, @size].unpack1('v')
          @size
        else
          0
        end
      end

      def serialize
        [@value].pack('v')
      end
    end
  end
end
