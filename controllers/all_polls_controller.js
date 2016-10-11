const User = require('../model/user');

module.exports = function(req,res,next){

  User.find({},{"polls":1,"_id":0},function(err,polls){
if(err){
  return next(err);
}
console.log('retrieved all polls')
res.send({allPolls:polls});
  })
}
