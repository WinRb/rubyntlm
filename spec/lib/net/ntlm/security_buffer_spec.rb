# frozen_string_literal: true

RSpec.describe Net::NTLM::SecurityBuffer do
  fields = [
    { name: :length, class: Net::NTLM::Int16LE, value: 0, active: true },
    { name: :allocated, class: Net::NTLM::Int16LE, value: 0, active: true },
    { name: :offset, class: Net::NTLM::Int32LE, value: 0, active: true }
  ]

  subject(:domain_security_buffer) do
    described_class.new({
      value: 'WORKSTATION',
      active: true
    })
  end

  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a field', 'WORKSTATION', true

  context 'when setting the value directly' do
    before do
      domain_security_buffer.value = 'DOMAIN1'
    end

    it 'changes the value' do
      expect(domain_security_buffer.value).to eq('DOMAIN1')
    end

    it 'adjusts the length field to the size of the new value' do
      expect(domain_security_buffer.length).to eq(7)
    end

    it 'adjusts the allocated field to the size of the new value' do
      expect(domain_security_buffer.allocated).to eq(7)
    end
  end

  describe '#data_size' do
    it 'returns the size of the value if active' do
      expect(domain_security_buffer.data_size).to eq(11)
    end

    it 'returns 0 if inactive' do
      domain_security_buffer.active = false
      expect(domain_security_buffer.data_size).to eq(0)
    end
  end

  describe '#parse' do
    let(:string_to_parse) do
      # Length of the string is 8
      length = "\x08\x00"
      # Space allocated is 8
      allocated = "\x08\x00"
      # The offset that the actual value begins at is also 8
      offset = "\x08\x00\x00\x00"
      "#{length}#{allocated}#{offset}FooBarBaz"
    end

    it 'reads in a properly formatted string' do
      aggregate_failures do
        expect(domain_security_buffer.parse(string_to_parse)).to eq(8)
        expect(domain_security_buffer.value).to eq('FooBarBa')
      end
    end
  end
end
