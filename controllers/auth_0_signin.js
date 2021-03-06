const User = require('../model/user');
const jwt = require('jwt-simple');


function tokenForUser(user){
  const timestamp = new Date().getTime();

  return jwt.encode({sub:user.id,iat:timestamp},process.env.SECRET);//user.id is a proxy for user._id which is generated by mongo
}                                                             //secret is combined with sub & iat to create token

module.exports = function(req,res,next){

  const userID = req.body.userID;//userID provided by auth0
  const name = req.body.name;
  const provider = req.body.provider;

  const query = provider +'.id';


User.findOne({[query]:userID},function(err,existingUser){//find with the query using fb or twitter id provided by auth0
  if(err){
    return next(err);
  }

  if(existingUser){
     return res.send({token:tokenForUser(existingUser),id:existingUser._id});
     //if exists, give token back and id
  }

User.findOne({"userName":name},function(err,existingUser){
  //if cannot with provided id, use user name
  if(err){
    return next(err);
  }
if(existingUser){
  //if find with username, save the new id in user and send back token
  existingUser[provider].id = userID;
  existingUser.save();
  return res.send({token:tokenForUser(existingUser),id:existingUser._id})
}



const user = new User({
  //if no name or provider id exists, create new user
  userName:name,
  email        :name +'@fakeemail.com',
  polls        : [],
  votedFor: [],
  itemCreated: [],
  [query]:userID
});//the query saves the user's unique twitter of fb ID

user.save(function(err){
  if(err){
    return next(err);
  }
  res.send({token:tokenForUser(user),id:user._id})
  })
})
})
}
