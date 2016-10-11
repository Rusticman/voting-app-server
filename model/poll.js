const mongoose = require('mongoose');
const Schema = mongoose.Schema;


//define model
const pollSchema = new Schema({
  pollTitle:String,
  items:{}


})


const ModelClass = mongoose.model('poll',pollSchema);

module.exports = ModelClass;
