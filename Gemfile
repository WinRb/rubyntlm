source 'https://rubygems.org'

gemspec

# Development dependencies live here rather than in the gemspec so that they
# can be grouped, and so that consumers of the gem never resolve them.
group :development, :test do
  gem 'pry'
  gem 'rake'
  gem 'rspec', '~> 3.13'
  gem 'simplecov', require: false

  # CI tooling.
  gem "bundler-audit", "~> 0.9.3", require: false
  gem "rubocop", "~> 1.86", ">= 1.86.2"
  gem "rubocop-rake", "~> 0.7.1"
  gem "rubocop-rspec", "~> 3.9"
  # ruby_audit 3.x requires Ruby >= 3.1. Only the CI audit job needs it.
  gem "ruby_audit", "~> 3.1", require: false if RUBY_VERSION >= "3.1.0"
end

# Release tooling only. Marked optional so it is not installed by default:
# github_changelog_generator drags in a large, slow-moving dependency tree that
# does not resolve on every Ruby we test against. Opt in when cutting a release
# with `bundle install --with changelog`.
group :changelog, optional: true do
  gem 'github_changelog_generator'
end

