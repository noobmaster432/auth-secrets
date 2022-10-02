//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
const port = 3000;

app.use(express.static("public")); 
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }))

app.use(session({
     secret: "Our little secret.",
     resave: false,
     saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
     email: String,
     password: String,
     googleId: String,
     secret: String
});

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
     done(null, user.id);
});
   
passport.deserializeUser(function(id, done) {
     User.findById(id, function(err, user) {
          done(err, user);
     });
});

passport.use(new GoogleStrategy({
     clientID: process.env.CLIENT_ID,
     clientSecret: process.env.CLIENT_SECRET,
     callbackURL: "http://localhost:3000/auth/google/secrets",
     userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
   },
   function(accessToken, refreshToken, profile, cb) {
     console.log(profile);
     User.findOrCreate({ googleId: profile.id }, function (err, user) {
       return cb(err, user);
     });
   }
 ));

app.get("/", (req, res) =>{
     res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get("/login", (req, res) =>{
     res.render("login");
});

app.get("/register", (req, res) =>{
     res.render("register");
});

app.get("/secrets", (req, res) =>{

     // if(req.isAuthenticated()){
     //      res.render("secrets");
     // } else {
     //      res.redirect("/login");
     // }

     User.find({"secret": {$ne: null}}, (err, foundUsers) =>{
          if(err) {
               console.log(err);
          } else {
               if (foundUsers) {
                    res.render("secrets", {usersWithSecrets: foundUsers});
               }
          }
     })
});

app.get("/submit", (req, res) =>{
     if(req.isAuthenticated()){
          res.render("submit");
     } else {
          res.redirect("/login");
     }
});

app.post("/submit", (req, res)=>{
     const submittedSecret = req.body.secret;
     console.log(req.user.id);
     User.findById(req.user.id, (err, foundUser) =>{
          if(err) {
               console.log(err);
          } else {
               if (foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(()=>{
                         res.redirect("/secrets");
                    });
               }
          }
     });
});

app.get("/logout", (req, res, next)=>{
     req.logout((err)=>{
       if (err) { return next(err); }
       res.redirect('/');
     });
});

app.post("/register", (req, res) =>{

     // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
     //      const newUser = new User({
     //           email: req.body.username,
     //           password: hash
     //      });
     //      newUser.save((err)=>{
     //           if(err){
     //                console.log(err);
     //           } else {
     //                res.render("secrets");
     //           }
     //      });
     //  });  

     User.register({username: req.body.username}, req.body.password, (err, user) =>{
          if(err){
               console.log(err);
               res.redirect("/register");
          } else {
               passport.authenticate("local")(req,res, ()=>{
                    res.redirect("/secrets");
               });
          }
     })
});

app.post("/login", (req, res) =>{

     // const username = req.body.username;
     // const password = req.body.password;

     // User.findOne({email: username}, (err, foundUser) =>{
     //      if (err) {
     //           console.log(err);
     //      } else {
     //           if (foundUser) {
     //                bcrypt.compare(password, foundUser.password, function(err, result) {  
     //                     if (result == true) {
     //                          res.render("secrets");
     //                     }  
     //                 });     
     //           }
     //      }
     // });

     const user = new User({
          username: req.body.username,
          password: req.body.password
     });

     req.login(user, (err)=>{
          if (err) {
               console.log(err);
          } else {
               passport.authenticate("local")(req, res, ()=>{
                    res.redirect("/secrets");
               });
          }
     })
});


app.listen(port, ()=>{
     console.log(`listening on http://localhost:${port}`);
});