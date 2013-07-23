module Net
module NTLM

  # base classes for primitives
  # @private
  class Field
    attr_accessor :active, :value

    def initialize(opts)
      @value  = opts[:value]
      @active = opts[:active].nil? ? true : opts[:active]
    end

    def size
      @active ? @size : 0
    end
  end


end
end