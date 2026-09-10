# frozen_string_literal: true

require File.expand_path("#{File.dirname(__FILE__)}/../../../../lib/net/ntlm/version")

RSpec.describe Net::NTLM::VERSION do
  let(:expected_string) do
    [described_class::MAJOR, described_class::MINOR, described_class::TINY].join('.')
  end

  it 'contains an integer value for Major Version' do
    expect(described_class::MAJOR).to be_an Integer
  end

  it 'contains an integer value for Minor Version' do
    expect(described_class::MINOR).to be_an Integer
  end

  it 'contains an integer value for Patch Version' do
    expect(described_class::TINY).to be_an Integer
  end

  it 'contains an aggregate version string' do
    aggregate_failures do
      expect(described_class::STRING).to be_a String
      expect(described_class::STRING).to eq(expected_string)
    end
  end
end
