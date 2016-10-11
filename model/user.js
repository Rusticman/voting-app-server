const mongoose = require('mongoose');
const Schema = mongoose.Schema;



//define model
const userSchema = new Schema({
        userName     : String,
        email        :{type:String,unique:true,lowercase:true},
        polls        : [],
        votedFor: [],
        itemCreated: [],
        facebook : {
            "id"    : String
                  },
          twitter : {
              "id"   : String
                   }
});

const ModelClass = mongoose.model('user',userSchema);

module.exports = ModelClass;
