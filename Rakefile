require "bundler/gem_tasks"


require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec)

task :default => :spec

desc "Generate code coverage"
RSpec::Core::RakeTask.new(:coverage) do |t|
  t.pattern = "./spec/unit/*_spec.rb"  # don't need this, it's default.
  t.rcov = true
  t.rcov_opts = ['--exclude', 'spec']
end