require 'rspec'
require 'net/ntlm'

describe Net::NTLM::Field do

  subject do
    Net::NTLM::Field.new({
      :value => 'Foo',
      :active => false
    })
  end

  it { should respond_to :active}
  it { should respond_to :value}
  it { should respond_to :size}

  context 'with no size specified' do
    it 'should set the value from initialize options' do
      subject.value.should == 'Foo'
    end

    it 'should set active from initialize options' do
      subject.active.should == false
    end

    it 'should set size to 0 if not active' do
      subject.size.should == 0
    end

    it 'should return 0 if active but no size specified' do
      subject.active = true
      subject.size.should == 0
    end
  end

  context 'with a size specified' do
    let (:field_with_size) { Net::NTLM::Field.new({ :value => 'Foo', :active => true, :size => 100 }) }

    it 'should return the size provided in the initialize options if active' do
      field_with_size.size.should == 100
    end

    it 'should still return 0 if not active' do
      field_with_size.active = false
      field_with_size.size.should == 0
    end

  end



end