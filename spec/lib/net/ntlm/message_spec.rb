require 'spec_helper'

describe Net::NTLM::Message do

  fields = []
  flags = []
  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a message', flags

end