# SecurID

SecurID is a library for authenticating with an RSA SecurID ACE
Authentication Server.

RSA SecurID is a two-factor authentication scheme that uses a PIN
and a tokencode to authenticate a user.  The tokencode is generated
by a hardware or software token and changes at regular timed intervals.

## Requirements

Installing the SecurID gem requires installation of the proper ACE
authentication library for your system.  The library may be obtained
from RSA.

## Installation

    $ gem build securid.gemspec
    $ gem install securid-X.X.gem

## Usage

    require 'rubygems'
    require 'securid'

    session = RSA::SecurID::Session.new
    session.authenticate(username, passcode)
    session.authenticated?                     # true on success

The `authenticate` instance method accepts a username and a passcode and
returns true or false to indicate success or failure.

The passcode is simply the concatenation of the user's PIN and their
current tokencode.

### Test Mode

Since it's not always possible to have an RSA ACE server running (local
development for example), the gem supports a test mode that will bypass
any communication with the ACE server and simply return a predetermined
response.

    require 'rubygems'
    require 'securid'

    session = RSA::SecurID::Session.new(test_mode: true)
    session.authenticate(username, passcode)   # never talks to the server
    session.authenticated?                     # test authentication is always successful by default

### Errors

Any unexpected problems during the authentication process will raise an
`RSA::SecurID::SecurIDError`.
