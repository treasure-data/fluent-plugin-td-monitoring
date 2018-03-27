Gem::Specification.new do |gem|
  gem.name          = "fluent-plugin-td-monitoring"
  gem.version       = File.read("VERSION").strip

  gem.authors       = ["Masahiro Nakagawa"]
  gem.email         = ["masa@treasure-data.com"]
  gem.description   = ''
  gem.summary       = gem.description
  gem.homepage      = "http://www.treasuredata.com/"
  gem.license       = 'MIT'
  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.has_rdoc = false
  gem.required_ruby_version = '>= 1.9.2'

  gem.add_dependency "fluentd", ">= 0.10.33"
  gem.add_dependency "mixlib-cli", "~> 1.7.0"
  gem.add_dependency "mixlib-config", "<= 2.2.4"
  gem.add_dependency "mixlib-log", "~> 1.7.1"
  gem.add_dependency "mixlib-shellout", "~> 2.2.7"
  gem.add_dependency "ohai", "~> 6.20.0"
  gem.add_dependency "httpclient", "~> 2.7"
  gem.add_development_dependency "rake", ">= 0.9.2"
  gem.add_development_dependency "simplecov", ">= 0.5.4"
  gem.add_development_dependency "rr", ">= 1.0.0"
end
