const User = require('../model/user');
const mongoose = require('mongoose');

module.exports = function(req,res,next){
  const pollID = req.body.pollID;
  const userID = req.body.userID;
  const pollItem = req.body.selectedItem;



User.findById(userID, function(err,user){//update user's voteFor array so can only vote once
  if(err){
    return next(err);
  }
if(user.votedFor.indexOf(pollID) !== -1){
  return res.send({message: "User has already voted in this poll."})
}
else{
  user.votedFor.push(pollID);

  const id = mongoose.Types.ObjectId(pollID), userIdent = mongoose.Types.ObjectId(userID),
  updateVote = "polls.$.items."+ pollItem, findItem ="polls.items."+ pollItem;


User.findOne({"polls._id":id},function(err,someonesPoll){//find the poll's user.id and pass it to the update func
  if(err){
    return next(err)
  }
const somePoll =mongoose.Types.ObjectId(someonesPoll._id);

User.update({"_id":somePoll,"polls._id" :id, [findItem]:{$exists:true}}, {$inc:{[updateVote]:1}},function(err,documents){
  if(err){//update the poll by incrementing it by one
    console.log('failed to update vote');
    return next(err);
  }
  user.save();
  res.send({message:"success"})
});



});
}
})


}
