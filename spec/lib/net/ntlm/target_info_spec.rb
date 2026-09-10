# frozen_string_literal: true

RSpec.describe Net::NTLM::TargetInfo do
  subject(:target_info) { described_class.new(data) }

  let(:computer_name_key) { Net::NTLM::TargetInfo::MSV_AV_NB_COMPUTER_NAME }
  let(:domain_name_key) { Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME }
  let(:data) do
    target_data({ computer_name_key => 'some data', domain_name_key => 'some other data' })
  end

  def target_data(pairs, terminated: true)
    dt = +''
    pairs.each do |key, value|
      dt << key
      dt << [value.length].pack('S')
      dt << value
    end
    dt << Net::NTLM::TargetInfo::MSV_AV_EOL << [0].pack('S') if terminated
    dt.force_encoding(Encoding::ASCII_8BIT)
  end

  describe 'invalid data' do
    context 'invalid pair id' do
      let(:data) { "\xFF\x00" }

      it 'returns an error' do
        expect { target_info }.to raise_error Net::NTLM::InvalidTargetDataError
      end
    end
  end

  describe '#av_pairs' do
    it 'returns the pair values with the given keys' do
      aggregate_failures do
        expect(target_info.av_pairs[computer_name_key]).to eq 'some data'
        expect(target_info.av_pairs[domain_name_key]).to eq 'some other data'
      end
    end

    context 'target data is nil' do
      subject(:target_info) { described_class.new(nil) }

      it 'returns an empty hash' do
        expect(target_info.av_pairs).to be_empty
      end
    end
  end

  describe '#to_s' do
    let(:data) do
      target_data({ computer_name_key => 'some data', domain_name_key => 'some other data' }, terminated: false)
    end
    let(:new_data) do
      target_data({ computer_name_key => 'some data', domain_name_key => 'some other data',
                    Net::NTLM::TargetInfo::MSV_AV_CHANNEL_BINDINGS => 'bindings' })
    end

    it 'returns bytes with any new data added' do
      target_info.av_pairs[Net::NTLM::TargetInfo::MSV_AV_CHANNEL_BINDINGS] = 'bindings'
      expect(target_info.to_s).to eq new_data
    end
  end
end
