var crypto = require('crypto');

exports.authenticator = function( secret, options ) {
  return new Authenticator( secret, options );
};

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
}

Authenticator.prototype.secret = "";
Authenticator.prototype.mac    = "sha512";
Authenticator.prototype.digest = "binary";
Authenticator.prototype.defaultExpireTime =  ( 3 * 24 * 60 ); // 3 days of minutes
Authenticator.prototype.getUserSalt = function( userId ) {
    return "";
};
Authenticator.prototype.createSession = function( userId ) {
  var data = JSON.stringify({
    userId: userId,
    expires: generate_expire_timestamp( this.defaultExpireTime )
  });
  return base64_encode(
    JSON.stringify({
      data: data,
      checksum: this._sign( data, this.getUserSalt( userId ) )
    })
  );
};
Authenticator.prototype.validateSession = function( token ) {
    var session = JSON.parse( base64_decode( token ) );
    var data = JSON.parse( session.data );
    if ( !validate_expire_timestamp( data.expires ) ) {
      return false;
    }
    if ( this._validate( session.data, this.getUserSalt( data.userId ), session.checksum ) ) {
      return data.userId;
    }
    return false;
};
Authenticator.prototype._sign  = function ( data, salt ) {
  var hmac = crypto.createHmac( this.mac, this.secret );
  hmac.update( salt );
  hmac.update( data );
  return hmac.digest( this.digest );
};
Authenticator.prototype._validate = function( data, salt, checksum ) {
  return this._sign(data, salt) == checksum;
};

function now_minute() {
  return ( new Date().getTime() / 1000 / 60 );
}
// expire_time is in minutes.
function generate_expire_timestamp( expire_time ) {
  return now_minute() + expire_time;
}

function validate_expire_timestamp( timestamp ) {
  return now_minute() <= timestamp;
}

function base64_encode( data ) {
  return (new Buffer( data )).toString('base64');
}

function base64_decode( data ) {
  return (new Buffer( data, 'base64' )).toString();
}
