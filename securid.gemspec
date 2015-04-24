Gem::Specification.new do |s|
  s.name = "securid"
  s.version = "0.2.0"

  s.authors = ["Ian Lesperance", "Edward Holets"]
  s.date = "2015-04-23"
  s.description = "A library for authenticating with an RSA SecurID ACE Authentication Server. Supports synchronous authenttication with ACE Server 6.1 and greater. Supports interactive and non-interactive flows."
  s.email = "ilesperance@ezpublishing.com"
  s.extensions = ["ext/securid/extconf.rb"]
  s.files = ["ext/securid/securid.c", "ext/securid/securid.h", "ext/securid/extconf.rb", "lib/securid.rb"]
  s.require_paths = ["lib"]
  s.summary = "A library for authenticating with an RSA SecurID ACE Authentication Server"
  s.homepage = "http://github.com/sendstream/securid"
  s.license = 'MIT'
end
