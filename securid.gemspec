Gem::Specification.new do |s|
  s.name = "securid"
  s.version = "0.2.6"

  s.authors = ["Ian Lesperance", "Edward Holets"]
  s.date = "2016-03-14"
  s.description = "A library for authenticating with an RSA SecurID ACE Authentication Server. Supports synchronous authenttication with ACE Server 6.1 and greater. Supports interactive and non-interactive flows."
  s.email = "opensource@labzero.com"
  s.extensions = ["ext/securid/extconf.rb"]
  s.files = ["ext/securid/securid.c", "ext/securid/securid.h", "ext/securid/extconf.rb", "lib/securid.rb", "README.md", "MIT-LICENSE"]
  s.require_paths = ["lib"]
  s.summary = "A library for authenticating with an RSA SecurID ACE Authentication Server"
  s.homepage = "https://github.com/labzero/securid"
  s.license = 'MIT'
  s.required_ruby_version = '>= 2.0.0'
end
