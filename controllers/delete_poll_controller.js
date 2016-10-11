const User = require('../model/user');
const mongoose = require('mongoose');

module.exports = function(req,res,next){
const pollID = req.params.pollID;
const id = mongoose.Types.ObjectId(pollID);
  User.update({}, { $pull: { "polls": {"_id":id}} }, function(err,doc){
if(err){
  return next(err);
}

  res.send({success:true})

  })
}
