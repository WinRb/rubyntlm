source 'https://rubygems.org'

gemspec

# Development dependencies live here rather than in the gemspec so that they
# can be grouped, and so that consumers of the gem never resolve them.
group :development, :test do
  gem 'pry'
  gem 'rake'
  gem 'rspec', '~> 3.13'
  gem 'simplecov', require: false
end

# Release tooling only. Marked optional so it is not installed by default:
# github_changelog_generator drags in a large, slow-moving dependency tree that
# does not resolve on every Ruby we test against. Opt in when cutting a release
# with `bundle install --with changelog`.
group :changelog, optional: true do
  gem 'github_changelog_generator'
end
