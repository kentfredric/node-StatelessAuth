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

var session = SessionToken.parse( token );
var userid = session.getSession()
  .userId;

if ( session.getSession()
  .expired() ) {
  console.log( ( new Date() )
    .getTime() / 60 / 1000 );
  console.log( session );
  throw "Login expired!"
}
if ( session.validate( signer, getUserSalt( userid ) ) ) {
  console.log( "Login success for user " + userid );
} else {
  throw "Login failed";
}