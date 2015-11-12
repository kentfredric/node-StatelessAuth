var Session = require( './Session.js' );

module.exports = SessionToken;

function SessionToken( properties ) {
  if ( !properties ) properties = {};
  this.session = properties.session;
  this.checksum = properties.checksum;
}

function base64_encode( content ) {
  return new Buffer( content )
    .toString( 'base64' );
}

function base64_decode( content ) {
  return new Buffer( content, 'base64' )
    .toString();
}

SessionToken.prototype.stringify = function() {
  return base64_encode( JSON.stringify( this ) );
};

SessionToken.parse = function( session_string ) {
  return new SessionToken( JSON.parse( base64_decode( session_string ) ) );
};

SessionToken.prototype.sign = function( signer, salt ) {
  this.checksum = signer.sign( this.session, salt );
  return this;
};

SessionToken.prototype.validate = function( signer, salt ) {
  return signer.validate( this.session, salt, this.checksum );
};

SessionToken.start = function( userId, expireTime ) {
  var self = new SessionToken( {} );
  self._session_cached = Session.start( userId, expireTime );
  self.session = self._session_cached.stringify();
  return self;
};

SessionToken.prototype.getSession = function() {
  if ( !this._session_cached ) this._session_cached = Session.parse( this.session );
  return this._session_cached;
};
