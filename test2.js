var SessionToken = require( "./SessionToken.js" );

var Signer = require( "./Signer.js" );

function getUserSalt( userid ) {
  // pretend database access here
  if ( userid == 56 ) {
    return "Noise";
  }
  if ( userid == 55 ) {
    return "Chaos";
  }
}

var signer = new Signer( {
  secret: 'Sekrit'
} );

// Pretend login

var token = SessionToken
  .start( 56, ( 3 * 24 * 60 ) )
  .sign( signer, getUserSalt( 56 ) )
  .stringify();

console.log( "Session key", token );


// Pretend use authkey

var sessionToken = SessionToken.parse( token );
var session = sessionToken.getSession();

var userid = session.userId;

if ( session.expired() ) {
  console.log( Session.now() );
  console.log( session );
  throw "Login expired!"
}
if ( sessionToken.validate( signer, getUserSalt( userid ) ) ) {
  console.log( "Login success for user " + userid );
} else {
  throw "Login failed";
}
