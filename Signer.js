var crypto = require('crypto');

module.exports = Signer;

function Signer(options) {
  if ( !options ) options = {};
  this.mac     = ( !!options.mac ) ? options.mac : 'sha512';
  this.digest  = ( !!options.digest ) ? options.digest : 'binary';
  this.secret  = ( !!options.secret ) ? options.secret : '';
}

Signer.prototype.sign = function ( data, salt ) {
  var hmac = crypto.createHmac( this.mac, this.secret );
  hmac.update( salt );
  hmac.update( data );
  return hmac.digest( this.digest );
};

Signer.prototype.validate = function( data, salt, checksum ) {
  return this.sign(data, salt) == checksum;
};