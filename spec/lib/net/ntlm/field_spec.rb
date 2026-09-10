# frozen_string_literal: true

RSpec.describe Net::NTLM::Field do
  it_behaves_like 'a field', 'Foo', false

  context 'with no size specified' do
    let(:field_without_size) { described_class.new({ value: 'Foo', active: true }) }

    it 'sets size to 0 if not active' do
      expect(field_without_size.size).to eq(0)
    end

    it 'returns 0 if active but no size specified' do
      field_without_size.active = true
      expect(field_without_size.size).to eq(0)
    end
  end

  context 'with a size specified' do
    let(:field_with_size) { described_class.new({ value: 'Foo', active: true, size: 100 }) }

    it 'returns the size provided in the initialize options if active' do
      expect(field_with_size.size).to eq(100)
    end

    it 'stills return 0 if not active' do
      field_with_size.active = false
      expect(field_with_size.size).to eq(0)
    end
  end
end
