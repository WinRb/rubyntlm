require 'spec_helper'

describe Net::NTLM::Blob do

  subject(:test_blob) do
    Net::NTLM::Blob.new
  end

  it { should respond_to :blob_signature }
  it { should respond_to :reserved }
  it { should respond_to :timestamp }
  it { should respond_to :challenge }
  it { should respond_to :unknown1 }
  it { should respond_to :target_info }
  it { should respond_to :unknown2 }

  context 'blob_signature' do
    it 'should be an int32LE Field' do
       test_blob[:blob_signature].class.should == Net::NTLM::Int32LE
    end

    it 'should have a default value of 257' do
      test_blob[:blob_signature].value.should == 257
    end

    it 'should be active' do
      test_blob[:blob_signature].active.should == true
    end
  end

  context 'reserved' do
    it 'should be an int32LE Field' do
      test_blob[:reserved].class.should == Net::NTLM::Int32LE
    end

    it 'should have a default value of 0' do
      test_blob[:reserved].value.should == 0
    end

    it 'should be active' do
      test_blob[:reserved].active.should == true
    end
  end

  context 'timestamp' do
    it 'should be an int64LE Field' do
      test_blob[:timestamp].class.should == Net::NTLM::Int64LE
    end

    it 'should have a default value of 0' do
      test_blob[:timestamp].value.should == 0
    end

    it 'should be active' do
      test_blob[:timestamp].active.should == true
    end
  end

  context 'challenge' do
    it 'should be a String Field' do
      test_blob[:challenge].class.should == Net::NTLM::String
    end

    it 'should have a default value of empty string' do
      test_blob[:challenge].value.should == ''
    end

    it 'should be active' do
      test_blob[:challenge].active.should == true
    end
  end

  context 'unknown1' do
    it 'should be an int32LE Field' do
      test_blob[:unknown1].class.should == Net::NTLM::Int32LE
    end

    it 'should have a default value of 0' do
      test_blob[:unknown1].value.should == 0
    end

    it 'should be active' do
      test_blob[:unknown1].active.should == true
    end
  end

  context 'target_info' do
    it 'should be a String Field' do
      test_blob[:target_info].class.should == Net::NTLM::String
    end

    it 'should have a default value of empty string' do
      test_blob[:target_info].value.should == ''
    end

    it 'should be active' do
      test_blob[:target_info].active.should == true
    end
  end

  context 'unknown2' do
    it 'should be an int32LE Field' do
      test_blob[:unknown2].class.should == Net::NTLM::Int32LE
    end

    it 'should have a default value of 0' do
      test_blob[:unknown2].value.should == 0
    end

    it 'should be active' do
      test_blob[:unknown2].active.should == true
    end
  end
end