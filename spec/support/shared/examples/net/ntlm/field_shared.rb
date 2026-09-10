# frozen_string_literal: true

RSpec.shared_examples_for 'a field' do |value, active|
  subject do
    described_class.new({
      value: value,
      active: active
    })
  end

  it { is_expected.to respond_to :active }
  it { is_expected.to respond_to :value }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :parse }
  it { is_expected.to respond_to :serialize }

  it 'sets the value from initialize options' do
    expect(subject.value).to eq(value)
  end

  it 'sets active from initialize options' do
    expect(subject.active).to eq(active)
  end
end
