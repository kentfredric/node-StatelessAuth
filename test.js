var x = require( "./StatelessAuth.js" );


var auth = x.authenticator( 'Sekrit', {
  mac: "md5",
  getUserSalt: function( userid ) {
    // pretend database access here
    if ( userid == 56 ) {
      return "Noise";
    }
    if ( userid == 55 ) {
      return "Chaos";
    }
  }
} );

session = auth.createSession( 56 );
console.log( "Session key", session );

var userid = auth.validateSession( session );
if ( userid != false ) {
  console.log( "Success", userid );
}