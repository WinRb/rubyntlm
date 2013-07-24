require 'spec_helper'

describe Net::NTLM::FieldSet do

  subject(:fieldset_class) do
    Class.new(Net::NTLM::FieldSet)
  end

  context 'the class' do
    it { should respond_to :string }
    it { should respond_to :int16LE }
    it { should respond_to :int32LE }
    it { should respond_to :int64LE }
    it { should respond_to :security_buffer }
    it { should respond_to :prototypes }
    it { should respond_to :names }
    it { should respond_to :types }
    it { should respond_to :opts }

    it 'should add a String Field correctly' do
      fieldset_class.string(:test_string, { :value => 'Test'})
      fieldset_class.prototypes.should include([:test_string, Net::NTLM::String, {:value=>"Test"}])
      fieldset_class.names.should include(:test_string)
      fieldset_class.types.should include(Net::NTLM::String)
      fieldset_class.opts.should include({:value => 'Test'})
      fieldset_object = fieldset_class.new
      fieldset_object.should respond_to :test_string
      fieldset_object.test_string.should == 'Test'
    end

    it 'should add a Int16LE Field correctly' do
      fieldset_class.int16LE(:test_int, { :value => 15})
      fieldset_class.prototypes.should include([:test_int, Net::NTLM::Int16LE, {:value=> 15}])
      fieldset_class.names.should include(:test_int)
      fieldset_class.types.should include(Net::NTLM::Int16LE)
      fieldset_class.opts.should include({:value => 15})
      fieldset_object = fieldset_class.new
      fieldset_object.should respond_to :test_int
      fieldset_object.test_string.should == 15
    end

    it 'should add a Int32LE Field correctly' do
      fieldset_class.int32LE(:test_int, { :value => 15})
      fieldset_class.prototypes.should include([:test_int, Net::NTLM::Int32LE, {:value=> 15}])
      fieldset_class.names.should include(:test_int)
      fieldset_class.types.should include(Net::NTLM::Int32LE)
      fieldset_class.opts.should include({:value => 15})
      fieldset_object = fieldset_class.new
      fieldset_object.should respond_to :test_int
      fieldset_object.test_string.should == 15
    end

    it 'should add a Int64LE Field correctly' do
      fieldset_class.int64LE(:test_int, { :value => 15})
      fieldset_class.prototypes.should include([:test_int, Net::NTLM::Int64LE, {:value=> 15}])
      fieldset_class.names.should include(:test_int)
      fieldset_class.types.should include(Net::NTLM::Int64LE)
      fieldset_class.opts.should include({:value => 15})
      fieldset_object = fieldset_class.new
      fieldset_object.should respond_to :test_int
      fieldset_object.test_string.should == 15
    end

    it 'should add a SecurityBuffer Field correctly' do
      fieldset_class.security_buffer(:test_buffer, {})
      fieldset_class.prototypes.should include([:test_buffer, Net::NTLM::SecurityBuffer, {}])
      fieldset_class.names.should include(:test_buffer)
      fieldset_class.types.should include(Net::NTLM::SecurityBuffer)
      fieldset_class.opts.should include({})
      fieldset_object = fieldset_class.new
      fieldset_object.should respond_to :test_int
      fieldset_object.test_string.should == 15
    end

  end

end