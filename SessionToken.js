var Session = require('./Session.js');

module.exports = SessionToken;

function SessionToken( properties ) {
  if (!properties) properties = {};
  this.session = properties.session;
  this.checksum = properties.checksum;
}

SessionToken.prototype.stringify = function() {
  var json = JSON.stringify( this );
  return (new Buffer( json )).toString('base64');
};

SessionToken.parse = function( session_string ) {
  var buffer = new Buffer( session_string, 'base64' );
  return new SessionToken( JSON.parse( buffer.toString() ) );
};

SessionToken.prototype.sign = function( signer, salt ) {
  this.checksum = signer.sign( this.session, salt );
  return this;
};

SessionToken.prototype.validate = function( signer, salt ) {
  return signer.validate( this.session, salt, this.checksum );
};

SessionToken.start = function( userId, expireTime ) {
  var self = new SessionToken({});
  self._session_cached = Session.start( userId, expireTime );
  self.session = self._session_cached.stringify();
  return self;
};
SessionToken.prototype.getSession = function() {
  if ( !this._session_cached ) this._session_cached = Session.parse( this.session );
  return this._session_cached;
};