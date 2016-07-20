var express= require('express');
var router=express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local');

var User = require('../models/user');

//get Register
router.get('/register',function(req,res){
  res.render('register');
});
//login
router.get('/login',function(req,res){
  res.render('login');
});

//Register user
router.post('/register',function(req,res){
  var name=req.body.name;
  var username=req.body.username;
  var email=req.body.email;
  var username=req.body.username;
  var password=req.body.password;
  var password2=req.body.password2;

  //validation
  req.checkBody('name','name is required').notEmpty();
  req.checkBody('username','username is required').notEmpty();
  req.checkBody('email','Email is required').notEmpty();
  req.checkBody('email','Email is not valid').isEmail();
  req.checkBody('password','password is required').notEmpty();
  req.checkBody('password2','password do not match').equals(req.body.password);

  var errors=req.validationErrors();

if (errors){
  console.log('You have errors');
res.render('register',{
  errors:errors
});
}
else {
  console.log('You have no register errors');
  var newUser=new User({
    name:name,
    username:username,
    email:email,
    password:password
  });
  User.createUser(newUser,function(err, user){
    if (err) throw err;
    console.log(user);
  });
  req.flash('success_msg', 'you are registered and now can login');
res.redirect('/users/login');
}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
  User.getUserByUsername(username, function(err, user){
    if(err) throw err;
    if(!user){
      return done(null,false,{message:'Unknown user'});
    }

    User.comparePassword(password, user.password, function(err, isMatch){
      if(err) throw err;
      if(isMatch){
        return done(null, user);
      }
      else{
        return done(null, false,{message:'Invalid password'});
      }
    });
  });
  }));

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    User.getUserById(id, function(err, user) {
      done(err, user);
    });
  });

router.post('/login',
  passport.authenticate('local', {successRedirect:'/',failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

  router.get('/logout', function(req, res){
    req.logout();

    req.flash('success_msg', 'You are logged out');

    res.redirect('/users/login');
  });


module.exports=router;
