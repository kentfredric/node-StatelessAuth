var Authenticator = require( './Authenticator.js' );

exports.authenticator = function( secret, options ) {
  return new Authenticator( secret, options );
};
