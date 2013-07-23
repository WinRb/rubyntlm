require 'net/ntlm/field_set'

module Net
module NTLM


  # @private false
  class Message < FieldSet
    class << Message
      def parse(str)
        m = Type0.new
        m.parse(str)
        case m.type
          when 1
            t = Type1.parse(str)
          when 2
            t = Type2.parse(str)
          when 3
            t = Type3.parse(str)
          else
            raise ArgumentError, "unknown type: #{m.type}"
        end
        t
      end

      def decode64(str)
        parse(Base64.decode64(str))
      end
    end

    def has_flag?(flag)
      (self[:flag].value & FLAGS[flag]) == FLAGS[flag]
    end

    def set_flag(flag)
      self[:flag].value  |= FLAGS[flag]
    end

    def dump_flags
      FLAG_KEYS.each{ |k| print(k, "=", flag?(k), "\n") }
    end

    def serialize
      deflag
      super + security_buffers.map{|n, f| f.value}.join
    end

    def encode64
      Base64.encode64(serialize).gsub(/\n/, '')
    end

    def decode64(str)
      parse(Base64.decode64(str))
    end

    alias head_size size

    def data_size
      security_buffers.inject(0){|sum, a| sum += a[1].data_size}
    end

    def size
      head_size + data_size
    end


    def security_buffers
      @alist.find_all{|n, f| f.instance_of?(SecurityBuffer)}
    end

    def deflag
      security_buffers.inject(head_size){|cur, a|
        a[1].offset = cur
        cur += a[1].data_size
      }
    end

    def data_edge
      security_buffers.map{ |n, f| f.active ? f.offset : size}.min
    end

    # sub class definitions
    class Type0 < Message
      string        :sign,      {:size => 8, :value => SSP_SIGN}
      int32LE       :type,      {:value => 0}
    end

    # @private false
    class Type1 < Message

      string          :sign,         {:size => 8, :value => SSP_SIGN}
      int32LE         :type,         {:value => 1}
      int32LE         :flag,         {:value => DEFAULT_FLAGS[:TYPE1] }
      security_buffer :domain,       {:value => ""}
      security_buffer :workstation,  {:value => Socket.gethostname }
      string          :padding,      {:size => 0, :value => "", :active => false }

      class << Type1
        # Parses a Type 1 Message
        # @param [String] str A string containing Type 1 data
        # @return [Type1] The parsed Type 1 message
        def parse(str)
          t = new
          t.parse(str)
          t
        end
      end

      # @!visibility private
      def parse(str)
        super(str)
        enable(:domain) if has_flag?(:DOMAIN_SUPPLIED)
        enable(:workstation) if has_flag?(:WORKSTATION_SUPPLIED)
        super(str)
        if ( (len = data_edge - head_size) > 0)
          self.padding = "\0" * len
          super(str)
        end
      end
    end


    # @private false
    class Type2 < Message

      string        :sign,         {:size => 8, :value => SSP_SIGN}
      int32LE       :type,      {:value => 2}
      security_buffer   :target_name,  {:size => 0, :value => ""}
      int32LE       :flag,         {:value => DEFAULT_FLAGS[:TYPE2]}
      int64LE           :challenge,    {:value => 0}
      int64LE           :context,      {:value => 0, :active => false}
      security_buffer   :target_info,  {:value => "", :active => false}
      string        :padding,   {:size => 0, :value => "", :active => false }

      class << Type2
        # Parse a Type 2 packet
        # @param [String] str A string containing Type 2 data
        # @return [Type2]
        def parse(str)
          t = new
          t.parse(str)
          t
        end
      end

      # @!visibility private
      def parse(str)
        super(str)
        if has_flag?(:TARGET_INFO)
          enable(:context)
          enable(:target_info)
          super(str)
        end
        if ( (len = data_edge - head_size) > 0)
          self.padding = "\0" * len
          super(str)
        end
      end

      # Generates a Type 3 response based on the Type 2 Information
      # @return [Type3]
      # @option arg [String] :username The username to authenticate with
      # @option arg [String] :password The user's password
      # @option arg [String] :domain ('') The domain to authenticate to
      # @option opt [String] :workstation (Socket.gethostname) The name of the calling workstation
      # @option opt [Boolean] :use_default_target (False) Use the domain supplied by the server in the Type 2 packet
      # @note An empty :domain option authenticates to the local machine.
      # @note The :use_default_target has presidence over the :domain option
      def response(arg, opt = {})
        usr = arg[:user]
        pwd = arg[:password]
        domain = arg[:domain] ? arg[:domain] : ""
        if usr.nil? or pwd.nil?
          raise ArgumentError, "user and password have to be supplied"
        end

        if opt[:workstation]
          ws = opt[:workstation]
        else
          ws = Socket.gethostname
        end

        if opt[:client_challenge]
          cc  = opt[:client_challenge]
        else
          cc = rand(MAX64)
        end
        cc = NTLM::pack_int64le(cc) if cc.is_a?(Integer)
        opt[:client_challenge] = cc

        if has_flag?(:OEM) and opt[:unicode]
          usr = NTLM::EncodeUtil.decode_utf16le(usr)
          pwd = NTLM::EncodeUtil.decode_utf16le(pwd)
          ws  = NTLM::EncodeUtil.decode_utf16le(ws)
          domain = NTLM::EncodeUtil.decode_utf16le(domain)
          opt[:unicode] = false
        end

        if has_flag?(:UNICODE) and !opt[:unicode]
          usr = NTLM::EncodeUtil.encode_utf16le(usr)
          pwd = NTLM::EncodeUtil.encode_utf16le(pwd)
          ws  = NTLM::EncodeUtil.encode_utf16le(ws)
          domain = NTLM::EncodeUtil.encode_utf16le(domain)
          opt[:unicode] = true
        end

        if opt[:use_default_target]
          domain = self.target_name
        end

        ti = self.target_info

        chal = self[:challenge].serialize

        if opt[:ntlmv2]
          ar = {:ntlmv2_hash => NTLM::ntlmv2_hash(usr, pwd, domain, opt), :challenge => chal, :target_info => ti}
          lm_res = NTLM::lmv2_response(ar, opt)
          ntlm_res = NTLM::ntlmv2_response(ar, opt)
        elsif has_flag?(:NTLM2_KEY)
          ar = {:ntlm_hash => NTLM::ntlm_hash(pwd, opt), :challenge => chal}
          lm_res, ntlm_res = NTLM::ntlm2_session(ar, opt)
        else
          lm_res = NTLM::lm_response(pwd, chal)
          ntlm_res = NTLM::ntlm_response(pwd, chal)
        end

        Type3.create({
                         :lm_response => lm_res,
                         :ntlm_response => ntlm_res,
                         :domain => domain,
                         :user => usr,
                         :workstation => ws,
                         :flag => self.flag
                     })
      end
    end

    # @private false
    class Type3 < Message

      string          :sign,          {:size => 8, :value => SSP_SIGN}
      int32LE         :type,          {:value => 3}
      security_buffer :lm_response,   {:value => ""}
      security_buffer :ntlm_response, {:value => ""}
      security_buffer :domain,        {:value => ""}
      security_buffer :user,          {:value => ""}
      security_buffer :workstation,   {:value => ""}
      security_buffer :session_key,   {:value => "", :active => false }
      int64LE         :flag,          {:value => 0, :active => false }

      class << Type3
        # Parse a Type 3 packet
        # @param [String] str A string containing Type 3 data
        # @return [Type2]
        def parse(str)
          t = new
          t.parse(str)
          t
        end

        # Builds a Type 3 packet
        # @note All options must be properly encoded with either unicode or oem encoding
        # @return [Type3]
        # @option arg [String] :lm_response The LM hash
        # @option arg [String] :ntlm_response The NTLM hash
        # @option arg [String] :domain The domain to authenticate to
        # @option arg [String] :workstation The name of the calling workstation
        # @option arg [String] :session_key The session key
        # @option arg [Integer] :flag Flags for the packet
        def create(arg, opt ={})
          t = new
          t.lm_response = arg[:lm_response]
          t.ntlm_response = arg[:ntlm_response]
          t.domain = arg[:domain]
          t.user = arg[:user]

          if arg[:workstation]
            t.workstation = arg[:workstation]
          end

          if arg[:session_key]
            t.enable(:session_key)
            t.session_key = arg[session_key]
          end

          if arg[:flag]
            t.enable(:session_key)
            t.enable(:flag)
            t.flag = arg[:flag]
          end
          t
        end
      end
    end
  end
end
end
