# frozen_string_literal: true

RSpec.shared_examples_for 'a fieldset' do |fields|
  subject(:fieldset_class) do
    Class.new(described_class)
  end

  context 'the class' do
    it { is_expected.to respond_to :string }
    it { is_expected.to respond_to :int16LE }
    it { is_expected.to respond_to :int32LE }
    it { is_expected.to respond_to :int64LE }
    it { is_expected.to respond_to :security_buffer }
    it { is_expected.to respond_to :prototypes }
    it { is_expected.to respond_to :names }
    it { is_expected.to respond_to :types }
    it { is_expected.to respond_to :opts }

    context 'adding a String Field' do
      before do
        fieldset_class.string(:test_string, { value: 'Test' })
      end

      it 'sets the prototypes correctly' do
        expect(fieldset_class.prototypes).to include([:test_string, Net::NTLM::String, { value: 'Test' }])
      end

      it 'sets the names correctly' do
        expect(fieldset_class.names).to include(:test_string)
      end

      it 'sets the types correctly' do
        expect(fieldset_class.types).to include(Net::NTLM::String)
      end

      it 'sets the opts correctly' do
        expect(fieldset_class.opts).to include({ value: 'Test' })
      end

      context 'when creating an instance' do
        let(:fieldset_object) do
          fieldset_class.new
        end

        it 'has the new accessor' do
          expect(fieldset_object).to respond_to(:test_string)
        end

        it 'has the correct default value' do
          expect(fieldset_object.test_string).to eq('Test')
        end
      end
    end

    context 'adding a Int16LE Field' do
      before do
        fieldset_class.int16LE(:test_int, { value: 15 })
      end

      it 'sets the prototypes correctly' do
        expect(fieldset_class.prototypes).to include([:test_int, Net::NTLM::Int16LE, { value: 15 }])
      end

      it 'sets the names correctly' do
        expect(fieldset_class.names).to include(:test_int)
      end

      it 'sets the types correctly' do
        expect(fieldset_class.types).to include(Net::NTLM::Int16LE)
      end

      it 'sets the opts correctly' do
        expect(fieldset_class.opts).to include({ value: 15 })
      end

      context 'when creating an instance' do
        let(:fieldset_object) do
          fieldset_class.new
        end

        it 'has the new accessor' do
          expect(fieldset_object).to respond_to(:test_int)
        end

        it 'has the correct default value' do
          expect(fieldset_object.test_int).to eq(15)
        end
      end
    end

    context 'adding a Int32LE Field' do
      before do
        fieldset_class.int32LE(:test_int, { value: 15 })
      end

      it 'sets the prototypes correctly' do
        expect(fieldset_class.prototypes).to include([:test_int, Net::NTLM::Int32LE, { value: 15 }])
      end

      it 'sets the names correctly' do
        expect(fieldset_class.names).to include(:test_int)
      end

      it 'sets the types correctly' do
        expect(fieldset_class.types).to include(Net::NTLM::Int32LE)
      end

      it 'sets the opts correctly' do
        expect(fieldset_class.opts).to include({ value: 15 })
      end

      context 'when creating an instance' do
        let(:fieldset_object) do
          fieldset_class.new
        end

        it 'has the new accessor' do
          expect(fieldset_object).to respond_to(:test_int)
        end

        it 'has the correct default value' do
          expect(fieldset_object.test_int).to eq(15)
        end
      end
    end

    context 'adding a Int64LE Field' do
      before do
        fieldset_class.int64LE(:test_int, { value: 15 })
      end

      it 'sets the prototypes correctly' do
        expect(fieldset_class.prototypes).to include([:test_int, Net::NTLM::Int64LE, { value: 15 }])
      end

      it 'sets the names correctly' do
        expect(fieldset_class.names).to include(:test_int)
      end

      it 'sets the types correctly' do
        expect(fieldset_class.types).to include(Net::NTLM::Int64LE)
      end

      it 'sets the opts correctly' do
        expect(fieldset_class.opts).to include({ value: 15 })
      end

      context 'when creating an instance' do
        let(:fieldset_object) do
          fieldset_class.new
        end

        it 'has the new accessor' do
          expect(fieldset_object).to respond_to(:test_int)
        end

        it 'has the correct default value' do
          expect(fieldset_object.test_int).to eq(15)
        end
      end
    end

    context 'adding a SecurityBuffer Field' do
      before do
        fieldset_class.security_buffer(:test_buffer, { value: 15 })
      end

      it 'sets the prototypes correctly' do
        expect(fieldset_class.prototypes).to include([:test_buffer, Net::NTLM::SecurityBuffer, { value: 15 }])
      end

      it 'sets the names correctly' do
        expect(fieldset_class.names).to include(:test_buffer)
      end

      it 'sets the types correctly' do
        expect(fieldset_class.types).to include(Net::NTLM::SecurityBuffer)
      end

      it 'sets the opts correctly' do
        expect(fieldset_class.opts).to include({ value: 15 })
      end

      context 'when creating an instance' do
        let(:fieldset_object) do
          fieldset_class.new
        end

        it 'has the new accessor' do
          expect(fieldset_object).to respond_to :test_buffer
        end

        it 'has the correct default value' do
          expect(fieldset_object.test_buffer).to eq(15)
        end
      end
    end
  end

  context 'an instance' do
    subject(:fieldset_object) do
      # FieldSet Base Class and Message Base Class
      # have no fields by default and thus cannot be initialized
      # currently. Clumsy workaround for now.
      described_class.string(:test_string, { value: 'Test', active: true, size: 4 }) if described_class.names.empty?
      described_class.new
    end

    it { is_expected.to respond_to :serialize }
    it { is_expected.to respond_to :parse }
    it { is_expected.to respond_to :size }
    it { is_expected.to respond_to :enable }
    it { is_expected.to respond_to :disable }

    context 'fields' do
      fields.each do |field|
        it { is_expected.to respond_to field[:name] }

        context field[:name].to_s do
          it "is a #{field[:class]}" do
            expect(fieldset_object[field[:name]].class).to eq(field[:class])
          end

          it "has a default value of #{field[:value]}" do
            expect(fieldset_object[field[:name]].value).to eq(field[:value])
          end

          it "has active set to #{field[:active]}" do
            expect(fieldset_object[field[:name]].active).to eq(field[:active])
          end
        end
      end
    end
  end
end
