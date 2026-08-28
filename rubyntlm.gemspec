require File.join(File.dirname(__FILE__), 'lib', 'net', 'ntlm', 'version')

Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.name = 'rubyntlm'
  s.version = Net::NTLM::VERSION::STRING
  s.summary = 'Ruby/NTLM library.'
  s.description = 'Ruby/NTLM provides message creator and parser for the NTLM authentication.'

  s.authors = ['Kohei Kajimoto','Paul Morton']
  s.email = ['koheik@gmail.com','paul.e.morton@gmail.com']
  s.homepage = 'https://github.com/winrb/rubyntlm'


  s.files         = `git ls-files`.split($/)
  s.require_paths = ["lib"]

  s.required_ruby_version = '>= 3.0.0'

  s.license = 'MIT'

  s.add_dependency "base64"

  s.metadata["rubygems_mfa_required"] = "true"
  s.metadata["source_code_uri"] = s.homepage
  s.metadata["changelog_uri"] = "#{s.homepage}/blob/master/CHANGELOG.md"
  s.metadata["bug_tracker_uri"] = "#{s.homepage}/issues"
end
