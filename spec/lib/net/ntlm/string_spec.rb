# frozen_string_literal: true

RSpec.describe Net::NTLM::String do
  let(:inactive) {
    described_class.new({
      value: 'Test',
      active: false,
      size: 4
    })
  }
  let(:active) {
    described_class.new({
      value: 'Test',
      active: true,
      size: 4
    })
  }

  it_behaves_like 'a field', 'Foo', false

  describe '#serialize' do
    it 'returns the value when active' do
      expect(active.serialize).to eq('Test')
    end

    it 'returns an empty string when inactive' do
      expect(inactive.serialize).to eq('')
    end

    it 'coerces non-string values into strings' do
      active.value = 15
      expect(active.serialize).to eq('15')
    end

    it 'returns empty string on a nil' do
      active.value = nil
      expect(active.serialize).to eq('')
    end
  end

  describe '#value=' do
    it 'sets active to false if it empty' do
      active.value = ''
      expect(active.active).to be(false)
    end

    it 'adjusts the size based on the value set' do
      aggregate_failures do
        expect(active.size).to eq(4)
        active.value = 'Foobar'
        expect(active.size).to eq(6)
      end
    end
  end

  describe '#parse' do
    it 'reads in a string of the proper size' do
      aggregate_failures do
        expect(active.parse('tseT')).to eq(4)
        expect(active.value).to eq('tseT')
      end
    end

    it 'does not read in a string that is too small' do
      aggregate_failures do
        expect(active.parse('B')).to eq(0)
        expect(active.value).to eq('Test')
      end
    end

    it 'is able to read from an offset and only for the given size' do
      aggregate_failures do
        expect(active.parse('FooBarBaz', 3)).to eq(4)
        expect(active.value).to eq('BarB')
      end
    end
  end
end
