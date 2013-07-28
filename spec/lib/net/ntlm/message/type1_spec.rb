require 'spec_helper'

describe Net::NTLM::Message::Type1 do
  fields = [
      { :name => :sign, :class => Net::NTLM::String, :value => Net::NTLM::SSP_SIGN, :active => true },
      { :name => :type, :class => Net::NTLM::Int32LE, :value => 1, :active => true },
      { :name => :flag, :class => Net::NTLM::Int32LE, :value =>  Net::NTLM::DEFAULT_FLAGS[:TYPE1], :active => true },
      { :name => :domain, :class => Net::NTLM::SecurityBuffer, :value => '', :active => true },
      { :name => :workstation, :class => Net::NTLM::SecurityBuffer, :value =>  Socket.gethostname, :active => true },
      { :name => :padding, :class => Net::NTLM::String, :value => '', :active => false },
  ]
  flags = [
      :UNICODE,
      :OEM,
      :REQUEST_TARGET,
      :NTLM,
      :ALWAYS_SIGN,
      :NTLM2_KEY
  ]
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

end