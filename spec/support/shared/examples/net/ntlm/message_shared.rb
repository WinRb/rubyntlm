# frozen_string_literal: true

RSpec.shared_examples_for 'a message' do |flags|
  subject(:test_message) do
    unless described_class.names.include?(:flag)
      described_class.int32LE(:flag, { value: Net::NTLM::DEFAULT_FLAGS[:TYPE1] })
    end
    described_class.new
  end

  it { is_expected.to respond_to :has_flag? }
  it { is_expected.to respond_to :set_flag }
  it { is_expected.to respond_to :dump_flags }
  it { is_expected.to respond_to :encode64 }
  it { is_expected.to respond_to :decode64 }
  it { is_expected.to respond_to :head_size }
  it { is_expected.to respond_to :data_size }
  it { is_expected.to respond_to :size }
  it { is_expected.to respond_to :security_buffers }
  it { is_expected.to respond_to :deflag }
  it { is_expected.to respond_to :data_edge }

  flags.each do |flag|
    it "is able to check if the #{flag} flag is set" do
      expect(test_message.has_flag?(flag)).to be(true)
    end
  end

  it 'is able to set a new flag' do
    test_message.set_flag(:DOMAIN_SUPPLIED)
    expect(test_message.has_flag?(:DOMAIN_SUPPLIED)).to be(true)
  end
end
