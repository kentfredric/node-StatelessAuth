var SessionToken = require( './SessionToken.js' );
var Signer = require( './Signer.js' );

module.exports = Authenticator;

function Authenticator( secret, options ) {

  if ( !options ) options = {};
  if ( options.defaultExpireTime ) this.defaultExpireTime = options.defaultExpireTime;
  if ( options.getUserSalt ) this.getUserSalt = options.getUserSalt;

  this.signer = new Signer( {
    mac: options.mac,
    digest: options.digest,
    secret: secret
  } );
}

Authenticator.prototype.defaultExpireTime = ( 3 * 24 * 60 ); // 3 days of minutes
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
  var session = sessionToken.getSession();
  if ( session.expired() ) {
    return false;
  }
  if ( sessionToken.validate( this.signer, this.getUserSalt( session.userId ) ) ) {
    return session.userId;
  }
  return false;
};
