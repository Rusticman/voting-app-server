const User = require('../model/user');
const Poll = require('../model/poll');

module.exports = function(req,res,next){
  const pollTitle = req.body.pollTitle;
  const items = req.body.items.split(',');//list of items from user
  const id = req.body.id;


const poll = new Poll({
  pollTitle:pollTitle,
  items:{}
})

items.forEach(function(option){//iterate over items and create keys in object
    poll.items[option.trim()] = 0;

})


  if(!pollTitle || !items || !id){
    return res.status(422).send({error:"You must provide a title and at least two options"});//split string into options separating with comma
  }

  User.update({_id:id}, {$push: {"polls": poll}} ,function(err,user){

    if(err){
    return  res.send({error:'There was an error with the database'})
    }
    if(!user){
      return res.send({message:'Could not find the user in the database'})
    }
     console.log('it worked!')

  })
return res.send({message:poll})


}
