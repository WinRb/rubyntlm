shared_examples_for 'a message' do |flags|

  subject(:test_message) do
    begin
      described_class.new
        # FieldSet Base Class and Message Base Class
        # have no fields by default and thus cannot be initialized
        # currently. Clumsy workaround for now.
    rescue NoMethodError
      described_class.int32LE(:flag, {:value => Net::NTLM::DEFAULT_FLAGS[:TYPE1] })
      described_class.new
    end
  end

  it { should respond_to :has_flag? }
  it { should respond_to :set_flag }
  it { should respond_to :dump_flags }
  it { should respond_to :has_flag? }
  it { should respond_to :encode64 }
  it { should respond_to :decode64 }
  it { should respond_to :head_size }
  it { should respond_to :data_size }
  it { should respond_to :size }
  it { should respond_to :security_buffers }
  it { should respond_to :deflag }
  it { should respond_to :data_edge }


end