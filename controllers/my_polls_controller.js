const User = require('../model/user');

module.exports = function(req,res,next){
const userID = req.params.userID;

  User.findById(userID,function(err,user){
if(err){
  return res.send({error:"there was an error retrieving the data."})
}
if(user.polls){
  res.send({polls:user.polls});
  }
  else{
    res.send({error:'There are no polls. '})
  }

  })
}
