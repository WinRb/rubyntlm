require 'spec_helper'

describe Net::NTLM::Message::Type2 do

  fields = [
      { :name => :sign, :class => Net::NTLM::String, :value => Net::NTLM::SSP_SIGN, :active => true },
      { :name => :type, :class => Net::NTLM::Int32LE, :value => 2, :active => true },
      { :name => :challenge, :class => Net::NTLM::Int64LE, :value => 0, :active => true },
      { :name => :context, :class => Net::NTLM::Int64LE, :value => 0, :active => false },
      { :name => :flag, :class => Net::NTLM::Int32LE, :value =>  Net::NTLM::DEFAULT_FLAGS[:TYPE2], :active => true },
      { :name => :target_name, :class => Net::NTLM::SecurityBuffer, :value => '', :active => true },
      { :name => :target_info, :class => Net::NTLM::SecurityBuffer, :value =>  '', :active => false },
      { :name => :padding, :class => Net::NTLM::String, :value => '', :active => false },
  ]
  flags = [
      :UNICODE
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags
end