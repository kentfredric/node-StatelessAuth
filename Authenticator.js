var crypto = require('crypto');

var Session = require('./Session.js');
var SessionToken = require('./SessionToken.js');
var Signer = require('./Signer.js');

module.exports = Authenticator;

function Authenticator( secret, options ) {
  this.secret = secret;
  if ( typeof options != 'undefined' ) {
    if ( typeof options.defaultExpireTime != 'undefined' ) {
      this.defaultExpireTime = options.defaultExpireTime;
    }
    if ( typeof options.getUserSalt != 'undefined' ) {
      this.getUserSalt = options.getUserSalt;
    }
    if ( typeof options.mac != 'undefined' ) {
      this.mac = options.mac;
    }
    if ( typeof options.digest != 'undefined' ) {
      this.digest = options.digest;
    }
  }
  this.signer = new Signer({
    mac: this.mac,
    digest: this.digest,
    secret: this.secret,
  });
}

Authenticator.prototype.secret = "";
Authenticator.prototype.mac    = "sha512";
Authenticator.prototype.digest = "binary";
Authenticator.prototype.defaultExpireTime =  ( 3 * 24 * 60 ); // 3 days of minutes
Authenticator.prototype.getUserSalt = function( userId ) {
    return "";
};
Authenticator.prototype.createSession = function( userId ) {
  var session = Session.start( userId, this.defaultExpireTime ).stringify();
  return SessionToken.create( session, this.signer.sign( session, this.getUserSalt( userId ) ) ).stringify();
};
Authenticator.prototype.validateSession = function( token ) {
    var sessionToken = SessionToken.parse( token );
    var session = Session.parse( sessionToken.session );
    if ( session.expired() ) {
      return false;
    }
    if ( this.signer.validate(  sessionToken.session, this.getUserSalt( session.userId ), sessionToken.checksum ) ) {
      return session.userId;
    }
    return false;
};