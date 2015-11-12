module.exports = Session;

function Session( properties ) {
  if (!properties) properties = {};
  this.userId = properties.userId;
  this.expiresAt = properties.expiresAt;
}

Session.prototype.expired = function() {
  if ( this.expiresAt == null ) {
    return true;
  }
  if ( this.expiresAt <= ( new Date().getTime() / 1000 / 60 ) ) {
    return true;
  }
  return false;
};

Session.prototype.stringify = function() {
  return JSON.stringify(this);
};

Session.parse = function( session_string ) {
  return new Session( JSON.parse( session_string ) );
};

Session.start = function( userId, sessionLength ) {
  return new Session({
    userId: userId,
    expiresAt: ( new Date().getTime() / 1000 / 60 ) + sessionLength
  });
};
