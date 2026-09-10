# frozen_string_literal: true

RSpec.shared_examples_for 'an integer field' do |values|
  subject do
    described_class.new({
      value: values[:default],
      active: true
    })
  end

  describe '#serialize' do
    it 'serializes properly with an integer value' do
      expect(subject.serialize).to eq(values[:default_hex])
    end

    it 'raises an Exception for a String' do
      subject.value = 'A'
      expect { subject.serialize }.to raise_error(values[:error])
    end

    it 'raises an Exception for Nil' do
      subject.value = nil
      expect { subject.serialize }.to raise_error(values[:error])
    end
  end

  describe '#parse' do
    it "parses a raw #{values[:bits]}-bit integer from a string" do
      aggregate_failures do
        expect(subject.parse(values[:alt_hex])).to eq(values[:size])
        expect(subject.value).to eq(values[:alt])
      end
    end

    it "uses an offset to find the #{values[:bits]}-bit integer in the string" do
      aggregate_failures do
        expect(subject.parse("Value:#{values[:alt_hex]}", 6)).to eq(values[:size])
        expect(subject.value).to eq(values[:alt])
      end
    end

    it 'returns 0 and not change the value if the string is not big enough' do
      aggregate_failures do
        expect(subject.parse(values[:small])).to eq(0)
        expect(subject.value).to eq(values[:default])
      end
    end
  end
end
