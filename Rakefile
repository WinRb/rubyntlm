require "bundler/gem_tasks"


require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec)

task :default => :spec

desc "Generate code coverage"
task :coverage do
  ENV['COVERAGE'] = 'true'
  Rake::Task["spec"].execute
end

desc "Open a Pry console for this library"
task :console do
  require 'pry'
  require 'net/ntlm'
  ARGV.clear
  Pry.start
end

