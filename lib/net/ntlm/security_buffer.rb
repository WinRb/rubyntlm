# frozen_string_literal: true

module Net
  module NTLM
    # NTLMSSP security buffer: length/allocated/offset triplet plus payload.
    class SecurityBuffer < FieldSet
      int16_le   :length,        { value: 0 }
      int16_le   :allocated,     { value: 0 }
      int32_le   :offset,        { value: 0 }

      attr_accessor :active

      def initialize(opts = {})
        super()
        @value  = opts[:value]
        @active = opts[:active].nil? || opts[:active]
        @size = 8
      end

      def parse(str, offset = 0)
        if @active && str.size >= offset + @size
          super(str, offset)
          @value = str[self.offset, length]
          @size
        else
          0
        end
      end

      def serialize
        super if @active
      end

      attr_reader :value

      def value=(val)
        @value = val
        self.length = self.allocated = val.size
      end

      def data_size
        @active ? @value.size : 0
      end
    end
  end
end
