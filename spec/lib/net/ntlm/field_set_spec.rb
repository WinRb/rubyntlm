# frozen_string_literal: true

RSpec.describe Net::NTLM::FieldSet do
  fields = []

  subject(:fieldset_class) do
    Class.new(described_class)
  end

  it_behaves_like 'a fieldset', fields

  context 'an instance' do
    subject(:fieldset_object) do
      fieldset_class.string(:test_string, { value: 'Test', active: true, size: 4 })
      fieldset_class.string(:test_string2, { value: 'Foo', active: true, size: 3 })
      fieldset_class.new
    end

    it 'serializes all the fields' do
      expect(fieldset_object.serialize).to eq('TestFoo')
    end

    it 'parses a string across the fields' do
      fieldset_object.parse('FooBarBaz')
      expect(fieldset_object.serialize).to eq('FooBarB')
    end

    it 'returns an aggregate size of all the fields' do
      expect(fieldset_object.size).to eq(7)
    end
  end
end
