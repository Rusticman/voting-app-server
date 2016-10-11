const User = require('../model/user');

module.exports = function(req,res,next){
      const pollID = req.params.pollID;
      const userID = req.params.userID;

User.findById(userID,function(err,user){
  if(err){
    return next(err);
  }

  if(user.votedFor.indexOf(pollID) === -1){
    res.send({message:false})
  }
  else{
    res.send({message:true})
  }

})



}
