//jshint esversion:6

require('dotenv').config();
currentYear = new Date().getFullYear();
const {parse, stringify} = require('flatted');
let {PythonShell} = require('python-shell')
const express = require("express"); 
var multer  =   require('multer');  
const download = require('download');
const fs = require('fs');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect(process.env.DB_LINK, {useNewUrlParser: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId:String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done)
{
    done(null,user.id);
});
passport.deserializeUser(function(id,done)
{
    User.findById(id,function(err,user)
    {
        done(err,user);
    });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALL_BACK_URL,
  userProfileUrl:   process.env.URL
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id,username:profile.id}, function (err, user) {
    return cb(err, user);
  });
}
));
submitted_csv_file="";
var storage =   multer.diskStorage({  
    destination: function (req, file, callback) {  
      callback(null, './Uploaded_files');  
    },  
    filename: function (req, file, callback) {  
    submitted_csv_file=file.originalname;
    console.log(submitted_csv_file);
      callback(null, file.originalname);  
    }  
  });  

  var upload = multer({ storage : storage}).single('myfile');  
app.get("/", function(req, res){
  res.render("home");
});
app.get("/secrets",function(req,res){
  complete_answer=""
// knn
knn_bin_cls=""
knn_mul_cls=""
knn_desc=""
knn_bin_acc="0.9760368900303525"
knn_mul_acc="0.9740368900303525"
// random forest
rf_bin_cls=""
rf_mul_cls=""
rf_desc=""
rf_bin_acc="0.9741029652113005"
rf_mul_acc="0.9731029652113005"
// cnn
cnn_bin_cls=""
cnn_mul_cls=""
cnn_desc=""
cnn_bin_acc="0.9582535605883726"
cnn_mul_acc="0.9506420733130982"
//lstm
lstm_bin_cls=""
lstm_mul_cls=""
lstm_desc=""
lstm_bin_acc="0.9562456222274107"
lstm_mul_acc="0.9590940929255195"

  res.render("secrets");
  let options={
    args:[]
  };
  console.log("entering!!");
  PythonShell.run('nids_random_updated.py',options, (err,response)=>{
    if (err)
    console.log(err);
    if(response){
      complete_answer=stringify(response);

      //knn
      temp_knn_bin_cls=stringify(response[0]);
      knn_bin_cls=temp_knn_bin_cls.slice(2,-2);

      temp_knn_mul_cls=stringify(response[1]);
      knn_mul_cls=temp_knn_mul_cls.slice(2,-2);

      temp_knn_desc=stringify(response[2]);
      knn_desc=temp_knn_desc.slice(2,-2);
      //random forest
      temp_rf_bin_cls=stringify(response[3]);
      rf_bin_cls=temp_rf_bin_cls.slice(2,-2);

      temp_rf_mul_cls=stringify(response[4]);
      rf_mul_cls=temp_rf_mul_cls.slice(2,-2);

      temp_rf_desc=stringify(response[5]);
      rf_desc=temp_rf_desc.slice(2,-2);
      //cnn
      temp_cnn_bin_cls=stringify(response[6]);
      cnn_bin_cls=temp_cnn_bin_cls.slice(2,-2);

      temp_cnn_mul_cls=stringify(response[7]);
      cnn_mul_cls=temp_cnn_mul_cls.slice(2,-2);

      temp_cnn_desc=stringify(response[8]);
      cnn_desc=temp_cnn_desc.slice(2,-2);
      //lstm
      temp_lstm_bin_cls=stringify(response[9]);
      lstm_bin_cls=temp_lstm_bin_cls.slice(2,-2);

      temp_lstm_mul_cls=stringify(response[10]);
      lstm_mul_cls=temp_lstm_mul_cls.slice(2,-2);

      temp_lstm_desc=stringify(response[11]);
      lstm_desc=temp_lstm_desc.slice(2,-2);
      console.log("entered!!");
      /*var things=require('./views/secrets_2.ejs');
      app.use('/secrets',things);*/
    }
  });
});
//app.get()
app.get("/secrets_2",function(req,res){
  res.render("secrets_2");
})
app.get("/paramsecrets",function(req,res){
  res.render("paramsecrets");
})
//if(l==final_ans){
p_complete_answer=""
// knn
p_knn_bin_cls=""
p_knn_mul_cls=""
p_knn_desc=""
p_knn_bin_acc="0.9760368900303525"
p_knn_mul_acc="0.9740368900303525"
// random forest
p_rf_bin_cls=""
p_rf_mul_cls=""
p_rf_desc=""
p_rf_bin_acc="0.9741029652113005"
p_rf_mul_acc="0.9731029652113005"
// cnn
p_cnn_bin_cls=""
p_cnn_mul_cls=""
p_cnn_desc=""
p_cnn_bin_acc="0.9582535605883726"
p_cnn_mul_acc="0.9506420733130982"
//lstm
p_lstm_bin_cls=""
p_lstm_mul_cls=""
p_lstm_desc=""
p_lstm_bin_acc="0.9562456222274107"
p_lstm_mul_acc="0.9590940929255195"

app.post("/parameters",function(req,res)
{
  const submitted_protocol_type=req.body.protocol_type;
  const submitted_service=req.body.service;
  const submitted_flag=req.body.flag;
  const submitted_logged_in=req.body.logged_in;
  const submitted_count=req.body.count;
  const submitted_srv_serror_rate=req.body.srv_serror_rate;
  const submitted_srv_rerror_rate=req.body.srv_rerror_rate;
  const submitted_same_srv_rate=req.body.same_srv_rate;
  const submitted_diff_srv_rate=req.body.diff_srv_rate;
  const submitted_dst_host_count=req.body.dst_host_count;
  const submitted_dst_host_srv_count=req.body.dst_host_srv_count;
  const submitted_dst_host_same_srv_rate=req.body.dst_host_same_srv_rate;
  const submitted_dst_host_diff_srv_rate=req.body.dst_host_diff_srv_rate;
  const submitted_dst_host_same_src_port_rate=req.body.dst_host_same_src_port_rate;
  const submitted_dst_host_serror_rate=req.body.dst_host_serror_rate;
  const submitted_dst_host_rerror_rate=req.body.dst_host_rerror_rate;

  let options={
    args:[submitted_protocol_type,submitted_service,submitted_flag,submitted_logged_in,submitted_count,submitted_srv_serror_rate,submitted_srv_rerror_rate,submitted_same_srv_rate,submitted_diff_srv_rate,submitted_dst_host_count,submitted_dst_host_srv_count,submitted_dst_host_same_srv_rate,submitted_dst_host_diff_srv_rate,submitted_dst_host_same_src_port_rate,submitted_dst_host_serror_rate,submitted_dst_host_rerror_rate]
  };
  console.log("entering!!");
  PythonShell.run('nids_parameter_updated.py',options, (err,response)=>{
    if (err)
    console.log(err);
    if(response){
      console.log("entered!!");
      p_complete_answer=stringify(response);

      //knn
      p_temp_knn_bin_cls=stringify(response[0]);
      p_knn_bin_cls=p_temp_knn_bin_cls.slice(2,-2);

      p_temp_knn_mul_cls=stringify(response[1]);
      p_knn_mul_cls=p_temp_knn_mul_cls.slice(2,-2);

      p_temp_knn_desc=stringify(response[2]);
      p_knn_desc=p_temp_knn_desc.slice(2,-2);
      //random forest
      p_temp_rf_bin_cls=stringify(response[3]);
      p_rf_bin_cls=p_temp_rf_bin_cls.slice(2,-2);

      p_temp_rf_mul_cls=stringify(response[4]);
      p_rf_mul_cls=p_temp_rf_mul_cls.slice(2,-2);

      p_temp_rf_desc=stringify(response[5]);
      p_rf_desc=p_temp_rf_desc.slice(2,-2);
      //cnn
      p_temp_cnn_bin_cls=stringify(response[6]);
      p_cnn_bin_cls=p_temp_cnn_bin_cls.slice(2,-2);

      p_temp_cnn_mul_cls=stringify(response[7]);
      p_cnn_mul_cls=p_temp_cnn_mul_cls.slice(2,-2);

      p_temp_cnn_desc=stringify(response[8]);
      p_cnn_desc=p_temp_cnn_desc.slice(2,-2);
      //lstm
      p_temp_lstm_bin_cls=stringify(response[9]);
      p_lstm_bin_cls=p_temp_lstm_bin_cls.slice(2,-2);

      p_temp_lstm_mul_cls=stringify(response[10]);
      p_lstm_mul_cls=p_temp_lstm_mul_cls.slice(2,-2);

      p_temp_lstm_desc=stringify(response[11]);
      p_lstm_desc=p_temp_lstm_desc.slice(2,-2);
    }
  });
  res.redirect("/paramsecrets");
});
app.get("/csv",function(req,res)
{
  if (req.isAuthenticated()){
    res.render("csv");
  } else {
    res.redirect("/login");
  }
});
app.get('/csv',function(req,res){  
        res.sendFile(__dirname + "/csv");  
  });

final_ans=""
app.post('/uploadjavatpoint',function(req,res){  
      upload(req,res,function(err) {  
          if(err) {  
              return res.end("Error uploading file.")
          }  
          res.end("File is uploaded successfully!"); 
  console.log("hello");
  const submitted_model=req.body.selected_model;
  console.log(submitted_model);
  console.log(submitted_csv_file);

  let options={
    args:[submitted_model,submitted_csv_file]
  };
  PythonShell.run('nids_csv_updated.py',options, (err,response)=>{
    if (err)
    console.log(err);
    if(response){
      temp_final_ans=stringify(response[0]);
      final_ans=temp_final_ans.slice(2,-2);
      console.log("completed");
      }
  }) 
})
});
l="completed!!"
app.get('/index',(req,res)=>{
  if(l==final_ans){
    console.log("yes");
    res.render('index');
  }
  //console.log("entering");
  
});
app.get('/download-file',(req,res)=>{
  console.log("entered");
  path='./Uploaded_files/'
path+=submitted_csv_file;
 res.download(path);
        });


app.get("/features",function(req,res){
  res.render("features");
})
app.get("/attacks",function(req,res){
  res.render("attacks");
})
app.get("/about",function(req,res){
  res.render("about");
})
app.get("/knn_bin_table",function(req,res){
  res.render("knn_bin_table");
});
app.get("/rf_bin_table",function(req,res){
  res.render("rf_bin_table");
});
app.get("/cnn_bin_table",function(req,res){
  res.render("cnn_bin_table");
});
app.get("/lstm_bin_table",function(req,res){
  res.render("lstm_bin_table");
});
app.get("/knn_table",function(req,res){
  res.render("knn_table");
});
app.get("/rf_table",function(req,res){
  res.render("rf_table");
});
app.get("/cnn_table",function(req,res){
  res.render("cnn_table");
});
app.get("/lstm_table",function(req,res){
  res.render("lstm_table");
});
app.get("/stats",function(req,res){
  res.render("stats");
});
app.get("/parameters",function(req,res){
  res.render("parameters");
})
app.get("/contact",function(req,res){
  res.render("contact");
})
app.get('/auth/google',
  passport.authenticate('google', { scope:
      ['profile' ] }
));
app.get("/auth/google/NIDS",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/submit");
  });
app.get("/login", function(req, res){
  res.render("login");

});



app.get("/register", function(req, res){
  res.render("register");
});
app.get("/submit",function(req,res)
{
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
  
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
  
  if(submitted_csv_file!=""){
    path='./Uploaded_files/'
path+=submitted_csv_file;
  fs.unlink(path, (err) => {
    if (err) {
        console.log(err);
    }
    console.log('file deleted');
    submitted_csv_file="";
});
  }


});

app.post("/register", function(req, res){
  User.register({username: req.body.username},req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/submit");
      });
    }
  });
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/submit");
      });
    }
  });
});

let port = process.env.PORT;
	if (port == null || port == "") {
  	port = 3000;
	}
app.listen(port, function() {
  console.log("Server started on port 3000.");
});