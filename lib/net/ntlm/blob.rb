# frozen_string_literal: true

module Net
  module NTLM
    BLOB_SIGN = 0x00000101

    # NTLMv2 client challenge blob structure.
    class Blob < FieldSet
      int32_le :blob_signature, { value: BLOB_SIGN }
      int32_le :reserved, { value: 0 }
      int64_le :timestamp, { value: 0 }
      string :challenge, { value: '', size: 8 }
      int32_le :unknown1, { value: 0 }
      string :target_info, { value: '', size: 0 }
      int32_le :unknown2, { value: 0 }

      def parse(str, offset = 0)
        # 28 is the length of all fields before the variable-length
        # target_info field.
        if str.size > 28
          enable(:target_info)
          # Grab everything except the last 4 bytes (which will be :unknown2)
          self[:target_info].value = str[28..-5]
        end
        super
      end
    end
  end
end
