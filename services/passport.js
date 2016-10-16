const passport = require('passport');
const User = require('../model/user');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;


//////////////////////////JWT STRATEGY\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

//setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),//this tells strategy to find token in authorization header
  secretOrKey: process.env.SECRET//this is secret to decode the token
};

//create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions,function(payload,done){
  //see if the userID in the payload(this is decoded JWT token which has sub & iat property) exists in our database
  //if it does call 'done'with that user
  //otherwise, call done without a user object

  User.findById(payload.sub, function(err,user){//sub property given in authentication.js
    if(err){
      return done(err,false);
    }

    if(user){
      done(null,user)//tells passport we found user and he is authenticated
    }
    else{
      done(null,false);//false means not authenticated
    }
  })
})

//tell passport to use these strategies
passport.use(jwtLogin);
