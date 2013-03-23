require "bundler/gem_tasks"

task :default => [:spec]


require 'rspec/core/rake_task'
 
desc 'Default: run specs.'
task :default => :spec
 
desc "Run specs unit tests"
RSpec::Core::RakeTask.new do |t|
  t.pattern = "./spec/unit/*_spec.rb" 
end
 
desc "Generate code coverage"
RSpec::Core::RakeTask.new(:coverage) do |t|
  t.pattern = "./spec/unit/*_spec.rb"  # don't need this, it's default.
  t.rcov = true
  t.rcov_opts = ['--exclude', 'spec']
end