module.exports = Session;

function Session( properties ) {
  if ( !properties ) properties = {};
  this.userId = properties.userId;
  this.expiresAt = properties.expiresAt;
}

Session.now = function() {
  var timestamp = new Date();
  return timestamp.getTime() / 1000 / 60;
};

Session.prototype.expired = function() {
  if ( this.expiresAt == null ) return true;

  if ( this.expiresAt <= Session.now() ) return true;

  return false;
};

Session.prototype.stringify = function() {
  return JSON.stringify( this );
};

Session.parse = function( session_string ) {
  return new Session( JSON.parse( session_string ) );
};

Session.start = function( userId, sessionLength ) {
  return new Session( {
    userId: userId,
    expiresAt: Session.now() + sessionLength
  } );
};
