# frozen_string_literal: true

module Net
  module NTLM
    # base class of data structure
    class FieldSet
      class << FieldSet
        # @macro string_security_buffer
        #   @method $1
        #   @method $1=
        #   @return [String]
        def string(name, opts)
          add_field(name, Net::NTLM::String, opts)
        end

        # @macro int16le_security_buffer
        #   @method $1
        #   @method $1=
        #   @return [Int16LE]
        def int16_le(name, opts)
          add_field(name, Net::NTLM::Int16LE, opts)
        end

        # Legacy camelCase alias for {.int16_le}; kept for backward compatibility.
        # rubocop:disable Naming/MethodName
        alias int16LE int16_le
        # rubocop:enable Naming/MethodName

        # @macro int32le_security_buffer
        #   @method $1
        #   @method $1=
        #   @return [Int32LE]
        def int32_le(name, opts)
          add_field(name, Net::NTLM::Int32LE, opts)
        end

        # Legacy camelCase alias for {.int32_le}; kept for backward compatibility.
        # rubocop:disable Naming/MethodName
        alias int32LE int32_le
        # rubocop:enable Naming/MethodName

        # @macro int64le_security_buffer
        #   @method $1
        #   @method $1=
        #   @return [Int64]
        def int64_le(name, opts)
          add_field(name, Net::NTLM::Int64LE, opts)
        end

        # Legacy camelCase alias for {.int64_le}; kept for backward compatibility.
        # rubocop:disable Naming/MethodName
        alias int64LE int64_le
        # rubocop:enable Naming/MethodName

        # @macro security_buffer
        #   @method $1
        #   @method $1=
        #   @return [SecurityBuffer]
        def security_buffer(name, opts)
          add_field(name, Net::NTLM::SecurityBuffer, opts)
        end

        def prototypes
          @proto
        end

        def names
          return [] if @proto.nil?

          @proto.map { |n, _t, _o| n }
        end

        def types
          return [] if @proto.nil?

          @proto.map { |_n, t, _o| t }
        end

        def opts
          return [] if @proto.nil?

          @proto.map { |_n, _t, o| o }
        end

        private

        def add_field(name, type, opts)
          (@proto ||= []).push [name, type, opts]
          define_accessor name
        end

        def define_accessor(name)
          module_eval(<<-RUBY, __FILE__, __LINE__ + 1)
          def #{name}
            self['#{name}'].value
          end

          def #{name}=(val)
            self['#{name}'].value = val
          end
          RUBY
        end
      end

      def initialize
        @alist = self.class.prototypes.map { |n, t, o| [n, t.new(o)] }
      end

      def parse(str, offset = 0)
        @alist.inject(offset) { |cur, a| cur + a[1].parse(str, cur) }
      end

      def serialize
        @alist.map { |_n, f| f.serialize }.join
      end

      def size
        @alist.inject(0) { |sum, a| sum + a[1].size }
      end

      def [](name)
        a = @alist.assoc(name.to_s.intern)
        raise ArgumentError, "no such field: #{name}" unless a

        a[1]
      end

      def []=(name, val)
        a = @alist.assoc(name.to_s.intern)
        raise ArgumentError, "no such field: #{name}" unless a

        a[1] = val
      end

      def enable(name)
        self[name].active = true
      end

      def disable(name)
        self[name].active = false
      end

      def disabled_fields?
        @alist.any? { |_name, field| !field.active }
      end

      alias has_disabled_fields? disabled_fields?
    end
  end
end
