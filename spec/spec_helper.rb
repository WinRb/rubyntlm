# Coverage must be started before the library under test is loaded, otherwise
# methods defined at require time are not tracked.
if ENV['COVERAGE']
  require 'simplecov'

  SimpleCov.start do
    add_filter '/spec/'
    add_filter '/vendor/'
    enable_coverage :branch if respond_to?(:enable_coverage)
  end
end

require 'rspec'
require 'net/ntlm'

# Custom matchers, shared examples and other support code.
Dir[File.expand_path('support/**/*.rb', __dir__)].sort.each { |path| require path }

RSpec.configure do |config|
  # Require `RSpec.describe` rather than a top-level `describe`, so the gem's
  # specs do not depend on RSpec monkey-patching Object.
  config.disable_monkey_patching!

  config.expect_with :rspec do |expectations|
    expectations.syntax = :expect
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.syntax = :expect
    # Fail fast when a partial double stubs a method the real object does not
    # have, so refactors in lib/ cannot leave specs passing against a fiction.
    mocks.verify_partial_doubles = true
  end

  # Shared example groups get their own metadata rather than leaking it into
  # the host group. This is the RSpec 4 default.
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # `rspec --only-failures` and `--next-failure`.
  config.example_status_persistence_file_path = 'spec/examples.txt'

  # Tagging an example `:focus` runs just that example, without needing to pass
  # a line number. No effect when nothing is tagged.
  config.filter_run_when_matching :focus

  # Randomise ordering to surface accidental dependencies between examples, and
  # print the seed so a failure can be reproduced with `--seed`.
  config.order = :random
  Kernel.srand config.seed
end
