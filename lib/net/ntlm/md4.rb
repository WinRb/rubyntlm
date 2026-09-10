# frozen_string_literal: true

require 'openssl'

module Net
  # Pure-Ruby MD4 digest, used to compute the NTLM hash.
  module NTLM
    # MD4 message digest.
    class Md4
      begin
        OpenSSL::Digest.digest('MD4', '')
      rescue StandardError
        # libssl-3.0+ doesn't support legacy MD4 -> use our own implementation

        require 'stringio'

        MD4_MASK = (1 << 32) - 1
        MD4_INITIAL_STATE = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476].freeze

        def self.digest(string)
          state = MD4_INITIAL_STATE.dup
          io = StringIO.new(md4_pad(string))
          block = +''

          while io.read(64, block)
            words = block.unpack('V16')
            md4_process_block(state, words)
          end

          state.pack('V4')
        end

        class << self
          private

          def md4_pad(string)
            string = string.b
            bit_len = string.bytesize << 3
            string += "\x80".b
            string += "\0" while (string.size % 64) != 56
            string = string.force_encoding('ascii-8bit') + [bit_len & MD4_MASK, bit_len >> 32].pack('V2')

            raise 'failed to pad to correct length' if string.size % 64 != 0

            string
          end

          def md4_process_block(state, words)
            saved = state.dup
            md4_round1(state, words)
            md4_round2(state, words)
            md4_round3(state, words)
            state.map!.with_index { |word, index| (word + saved[index]) & MD4_MASK }
          end

          def md4_round1(state, words)
            mix = method(:md4_f)
            4.times do |round|
              base = round * 4
              md4_step(state, 0, words[base], 3, mix)
              md4_step(state, 3, words[base + 1], 7, mix)
              md4_step(state, 2, words[base + 2], 11, mix)
              md4_step(state, 1, words[base + 3], 19, mix)
            end
            state
          end

          def md4_round2(state, words)
            mix = ->(first, second, third) { md4_g(first, second, third) + 0x5a827999 }
            4.times do |round|
              md4_step(state, 0, words[round], 3, mix)
              md4_step(state, 3, words[round + 4], 5, mix)
              md4_step(state, 2, words[round + 8], 9, mix)
              md4_step(state, 1, words[round + 12], 13, mix)
            end
            state
          end

          def md4_round3(state, words)
            mix = ->(first, second, third) { md4_h(first, second, third) + 0x6ed9eba1 }
            [0, 2, 1, 3].each do |round|
              md4_step(state, 0, words[round], 3, mix)
              md4_step(state, 3, words[round + 8], 9, mix)
              md4_step(state, 2, words[round + 4], 11, mix)
              md4_step(state, 1, words[round + 12], 15, mix)
            end
            state
          end

          def md4_step(state, target, word, shift, mix)
            others = [state[(target + 1) % 4], state[(target + 2) % 4], state[(target + 3) % 4]]
            state[target] = md4_rotate(state[target] + mix.call(*others) + word, shift)
          end

          def md4_f(first, second, third)
            (first & second) | ((first ^ MD4_MASK) & third)
          end

          def md4_g(first, second, third)
            (first & second) | (first & third) | (second & third)
          end

          def md4_h(first, second, third)
            first ^ second ^ third
          end

          def md4_rotate(value, shift)
            ((value << shift) & MD4_MASK) | ((value & MD4_MASK) >> (32 - shift))
          end
        end
      else
        # Openssl/libssl provides MD4, so we can use it.
        def self.digest(string)
          OpenSSL::Digest::MD4.digest(string)
        end
      end
    end
  end
end
