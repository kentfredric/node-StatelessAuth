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

SessionToken.create = function( session ) {
  return new SessionToken({
    session: session,
  });
};

SessionToken.prototype.sign = function( signer, salt ) {
  this.checksum = signer.sign( this.session, salt );
  return this;
};

SessionToken.prototype.validate = function( signer, salt ) {
  return signer.validate( this.session, salt, this.checksum );
};