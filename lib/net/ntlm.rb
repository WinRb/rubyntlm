# frozen_string_literal: true

#
# = net/ntlm.rb
#
# An NTLM Authentication Library for Ruby
#
# This code is a derivative of "dbf2.rb" written by yrock
# and Minero Aoki. You can find original code here:
# http://jp.rubyist.net/magazine/?0013-CodeReview
# -------------------------------------------------------------
# Copyright (c) 2005,2006 yrock
#
#
# 2006-02-11 refactored by Minero Aoki
# -------------------------------------------------------------
#
# All protocol information used to write this code stems from
# "The NTLM Authentication Protocol" by Eric Glass. The author
# would thank to him for this tremendous work and making it
# available on the net.
# http://davenport.sourceforge.net/ntlm.html
# -------------------------------------------------------------
# Copyright (c) 2003 Eric Glass
#
# -------------------------------------------------------------
#
# The author also looked Mozilla-Firefox-1.0.7 source code,
# namely, security/manager/ssl/src/nsNTLMAuthModule.cpp and
# Jonathan Bastien-Filiatrault's libntlm-ruby.
# "http://x2a.org/websvn/filedetails.php?
# repname=libntlm-ruby&path=%2Ftrunk%2Fntlm.rb&sc=1"
# The latter has a minor bug in its separate_keys function.
# The third key has to begin from the 14th character of the
# input string instead of 13th:)
#--
# $Id: ntlm.rb,v 1.1 2006/10/05 01:36:52 koheik Exp $
#++

require 'base64'
require 'openssl'
require 'openssl/digest'
require 'socket'

# Load Order is important here
require 'net/ntlm/exceptions'
require 'net/ntlm/field'
require 'net/ntlm/int16_le'
require 'net/ntlm/int32_le'
require 'net/ntlm/int64_le'
require 'net/ntlm/string'

require 'net/ntlm/field_set'
require 'net/ntlm/blob'
require 'net/ntlm/security_buffer'
require 'net/ntlm/message'
require 'net/ntlm/message/type0'
require 'net/ntlm/message/type1'
require 'net/ntlm/message/type2'
require 'net/ntlm/message/type3'

require 'net/ntlm/encode_util'
require 'net/ntlm/md4'
require 'net/ntlm/rc4'
require 'net/ntlm/response'

require 'net/ntlm/client'
require 'net/ntlm/channel_binding'
require 'net/ntlm/target_info'

module Net
  # Ruby/NTLM library: message creator and parser for NTLM authentication.
  module NTLM
    LM_MAGIC = "KGS!@\#$%"
    TIME_OFFSET = 11_644_473_600
    MAX64 = 0xffffffffffffffff

    class << self
      # Valid format for LAN Manager hex digest portion: 32 hexadecimal characters.
      LAN_MANAGER_HEX_DIGEST_REGEXP = /[0-9a-f]{32}/i
      # Valid format for NT LAN Manager hex digest portion: 32 hexadecimal characters.
      NT_LAN_MANAGER_HEX_DIGEST_REGEXP = /[0-9a-f]{32}/i
      # Valid format for an NTLM hash composed of `'<LAN Manager hex digest>:<NT LAN Manager hex digest>'`.
      DATA_REGEXP = /\A#{LAN_MANAGER_HEX_DIGEST_REGEXP}:#{NT_LAN_MANAGER_HEX_DIGEST_REGEXP}\z/

      # Takes a string and determines whether it is a valid NTLM Hash
      # @param [String] the string to validate
      # @return [Boolean] whether or not the string is a valid NTLM hash
      def ntlm_hash?(data)
        decoded_data = data.dup
        decoded_data = EncodeUtil.decode_utf16le(decoded_data)
        if DATA_REGEXP.match(decoded_data)
          true
        else
          false
        end
      end

      alias is_ntlm_hash? ntlm_hash?

      # Convert the value to a 64-bit little-endian integer
      # @param [String] val The string to convert
      def pack_int64le(val)
        [val & 0x00000000ffffffff, val >> 32].pack('V2')
      end

      # Builds an array of strings that are 7 characters long
      # @param [String] str The string to split
      # @api private
      def split7(str)
        s = str.dup
        (ret ||= []).push s.slice!(0, 7) until s.empty?
        ret
      end

      # Each byte of a DES key contains seven bits of key material and one odd-parity bit.
      # The parity bit should be set so that there are an odd number of 1 bits in each byte.
      # @param [String] str String to generate keys for
      # @api private
      def gen_keys(str)
        split7(str).map { |str7|
          bits = split7(str7.unpack1('B*')).inject('')\
            { |ret, tkn| ret + tkn + (tkn.gsub('1', '').size % 2).to_s }
          [bits].pack('B*')
        }
      end

      def apply_des(plain, keys)
        keys.map { |k|
          # Spec requires des-cbc, but openssl 3 does not support single des
          # by default, so just do triple DES (EDE) with the same key
          dec = OpenSSL::Cipher.new('des-ede-cbc').encrypt
          dec.padding = 0
          dec.key = k + k
          dec.update(plain) + dec.final
        }
      end

      # Generates a {https://en.wikipedia.org/wiki/LAN_Manager LAN Manager Hash}
      # @param [String] password The password to base the hash on
      def lm_hash(password)
        keys = gen_keys password.upcase.ljust(14, "\0")
        apply_des(LM_MAGIC, keys).join
      end

      # Generate an NTLM Hash
      # @param [String] password The password to base the hash on
      # @option opt :unicode (false) Unicode encode the password
      def ntlm_hash(password, opt = {})
        pwd = password.dup
        pwd = EncodeUtil.encode_utf16le(pwd) unless opt[:unicode]
        Net::NTLM::Md4.digest pwd
      end

      # Generate a NTLMv2 Hash
      # @param [String] user The username
      # @param [String] password The password
      # @param [String] target The domain or workstation to authenticate to
      # @option [Boolean] opt :unicode (false) Unicode encode the domain.
      def ntlmv2_hash(user, password, target, opt = {})
        ntlmhash = ntlmv2_key(password, opt)
        userdomain = ntlmv2_userdomain(user, target, opt)
        OpenSSL::HMAC.digest(OpenSSL::Digest.new('MD5'), ntlmhash, userdomain)
      end

      private

      def ntlmv2_key(password, opt)
        if ntlm_hash? password
          decoded = EncodeUtil.decode_utf16le(password)
          [decoded.upcase[33, 65]].pack('H32')
        else
          ntlm_hash(password, opt)
        end
      end

      def ntlmv2_userdomain(user, target, opt)
        userdomain = ntlmv2_upcase_user(user, opt) + target
        opt[:unicode] ? userdomain : EncodeUtil.encode_utf16le(userdomain)
      end

      def ntlmv2_upcase_user(user, opt)
        if opt[:unicode]
          # Uppercase operation on username containing non-ASCI characters
          # after behing unicode encoded with `EncodeUtil.encode_utf16le`
          # doesn't play well. Upcase should be done before encoding.
          EncodeUtil.encode_utf16le(EncodeUtil.decode_utf16le(user).upcase)
        else
          user.upcase
        end
      end
    end
  end
end
