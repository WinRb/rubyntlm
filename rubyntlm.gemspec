require File.join(File.dirname(__FILE__), 'lib', 'net', 'ntlm')

Gem::Specification.new do |s|
  s.platform = Gem::Platform::RUBY
  s.name = 'rubyntlm'
  s.version = Net::NTLM::VERSION::STRING
  s.summary = 'Ruby/NTLM library.'
  s.description = 'Ruby/NTLM provides message creator and parser for the NTLM authentication.'

  s.author = 'Kohei Kajimoto'
  s.email = 'koheik@gmail.com'
  s.homepage = 'http://rubyforge.org/projects/rubyntlm'
  s.rubyforge_project = 'rubyntlm'

  s.files = Dir['Rakefile', 'README', 'lib/**/*', 'examples/**/*', 'test/**/*']

  s.has_rdoc = true
  s.extra_rdoc_files = %w( README )
  s.rdoc_options.concat ['--main', 'README']
end
