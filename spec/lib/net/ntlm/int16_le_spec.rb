require 'spec_helper'

describe Net::NTLM::Int16LE do

  it_behaves_like 'a field', 15, false

  subject do
    Net::NTLM::Int16LE.new({
        :value  => 15,
        :active => true
    })
  end

  context '#serialize' do
    it 'should serialize properly with an integer value' do
      subject.serialize.should == "\x0F\x00"
    end

    it 'should raise a TypeError for a String' do
      subject.value = 'A'
      expect {subject.serialize}.to raise_error(TypeError)
    end

    it 'should raise a TypeError for Nil' do
      subject.value = nil
      expect {subject.serialize}.to raise_error(TypeError)
    end
  end

  context '#parse' do
    it 'should parse a raw byte 16-bit integer from a string' do
      subject.parse("\x0E\x00").should == 2
      subject.value.should == 14
    end

    it 'should use an offset to find the integer in the string' do
      subject.parse("Value:\x0D\x00",6).should == 2
      subject.value.should == 13
    end

    it 'should return 0 and not change the value if the string is not big enough' do
      subject.parse("\x0F").should == 0
      subject.value.should == 15
    end
  end

end