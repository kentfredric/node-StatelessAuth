var SessionToken = require('./SessionToken.js');
var Signer = require('./Signer.js');

module.exports = Authenticator;

function Authenticator( secret, options ) {
  this.secret = secret;
  if ( !options ) options = {};
  if ( options.defaultExpireTime ) this.defaultExpireTime = options.defaultExpireTime;
  if ( options.getUserSalt )       this.getUserSalt       = options.getUserSalt;
  if ( options.mac )               this.mac               = options.mac;
  if ( options.digest )            this.digest            = options.digest;

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
  return SessionToken
          .start( userId, this.defaultExpireTime )
          .sign( this.signer, this.getUserSalt( userId ) )
          .stringify();
};
Authenticator.prototype.validateSession = function( token ) {
    var sessionToken = SessionToken.parse( token );
    if ( sessionToken.getSession().expired() ) {
      return false;
    }
    if ( sessionToken.validate( this.signer , sessionToken.checksum ) ) {
      return sessionToken.getSession().userId;
    }
    return false;
};