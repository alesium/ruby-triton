require File.expand_path('../lib/ruby-triton/version', __FILE__)

Gem::Specification.new do |s|
  s.name        = 'ruby-triton'
  s.version     = RubyTriton::VERSION
  s.date        = '2015-03-15'
  s.summary     = "Interface for Joyent's Triton service."
  s.description = "A simple low-abstraction layer which communicates with Joyent's Triton service."
  s.authors     = ['Alesium']
  s.email       = 'sperreault@alesium.net'
  s.homepage    = 'http://github.com/alesium/ruby-triton/'
  s.license     = 'MIT'

  s.add_dependency             'net-ssh',    '>= 2.6.0'
  s.add_dependency             'rest-client','>= 2.0.0'

  s.add_development_dependency 'rake'
  s.add_development_dependency 'minitest',   '~> 5.5.1'

  s.files       = ['LICENSE',
                   'README.md',
                   'ruby-triton.gemspec',
                   'example.rb',
                   'lib/ruby-triton.rb',
                   'lib/ruby-triton/version.rb',
                   'lib/ruby-triton/triton_client.rb',
                   'test/unit/triton_client_test.rb']

  s.test_files  = s.files.grep(%r{^test})
  s.require_paths = %w{lib}
end
