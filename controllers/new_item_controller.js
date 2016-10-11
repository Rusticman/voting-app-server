const User = require('../model/user');
const mongoose = require('mongoose');


module.exports = function(req,res,next){
  const  pollID = req.body.pollID;
  const newItem = req.body.newItem;
  const userID = req.body.userID;
  
  const addItem = "polls.$.items."+ newItem;
  const id = mongoose.Types.ObjectId(pollID);
  const userIdent = mongoose.Types.ObjectId(userID);


  User.findOne({"_id":userIdent}, function(err,user2){
      if(err){
        next(err);
      }

      if(user2.itemCreated.indexOf(pollID) !== -1){

        return res.send({message:'user has already created item for this poll.'})
      }

  User.findOne({"polls._id":id},function(err,user){
    if(err){
      return next(err);
    }
    User.update({"_id":user._id, "polls._id":id},{$set:{[addItem]:0}}, function(err,user){
        if(err){
          return next(err);
        }
        user2.itemCreated.push(pollID);
        user2.save();
        return res.send({message:'success'})


  })

    })

  })




}
