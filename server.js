import Express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose"
import session from "express-session";
import 'dotenv/config';
import cors from "cors";
import jwt from "jsonwebtoken";
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';






const app = Express();
app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());

app.use(cors());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
  });

app.use(session({
    secret: process.env.SECRET_KEY, 
    resave: false,
    saveUninitialized: true,
  }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://trantu1242003:TU1242kkk3@cluster0.6wvbq5t.mongodb.net/SecretApp?retryWrites=true&w=majority");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);


// passport-local
passport.use(User.createStrategy());

// passport-jwt
const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET_TOKEN,
}
passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
  
    const result = User.findById(jwt_payload.user.id); 
    if (result) {
        return done(null, result);
    } else {
        return done(null, false);
    }
    
  }));


passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

const authenticateToken = (req, res, next) => {
  
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
      if (err) { return next(err); }
      if (!user) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      req.login(user, { session: false }, (loginErr) => {
        if (loginErr) {
          return next(loginErr);
        }
        return next();
      });
    })(req, res, next);
  };

app.route("/login")
    .get( authenticateToken, (req, res) => {
        res.json({ message: 'Sucess' });
      })

    .post((req, res) =>{
        console.log(req.body);
        if(req.isAuthenticated()){ 
            console.log("You are logged in");
        }
        else {
            passport.authenticate("local", (err, user, info) => {
                if (err) {
                    console.log(err);
                    res.status(401).json({ success: false, message: 'Invalid credentials' });
                    //
                } else if (!user) {
                    //
                    console.log("Login failed!");
                    res.status(401).json({ success: false, message: "Invalid credentials" });
                } else {
                    console.log("Authenticated!");
                    const token = jwt.sign({ user: {id:user._id} }, process.env.SECRET_TOKEN, { expiresIn: '1h' });
                    console.log(user.id);
                    res.json({token: `Bearer ${token}`,});
                    
                
                }
            })(req, res);
        }

})

app.post("/register", async (req, res) => {
        
        console.log(req.body);
        try {
            const newUser = await User.register(new User({ username: req.body.username }), req.body.password);
            console.log(req.body);
            passport.authenticate("local", (err, user, info) => {
                if (err) {
                    console.log(err);
                    res.status(401).json({ success: false, message: 'Invalid credentials' });
                    //
                } else if (!user) {
                    //
                    console.log("Failed!");
                    res.status(401).json({ success: false, message: "Invalid credentials" });
                } else {
                    console.log("Authenticated!");
                    const token = jwt.sign({ user: {id:user._id} }, process.env.SECRET_TOKEN, { expiresIn: '1h' });
                    console.log(user.id);
                    res.json({token: `Bearer ${token}`,});
                
                }
            })(req, res);
        } catch (err) {
            console.error(err);
            if (err.name === "UserExistsError") {
                
                console.log("Username already exists. Please choose another username.");
                res.json({error: "Username already exists. Please choose another username.",});
            }
            
        }
        
       
    });

app.route("/logout")
    .get((req, res) => {
        console.log(req.isAuthenticated());
        req.logout(function(err) {
            if (err) console.log(err);
            else {
                console.log("Log out successfully");
                res.json({ success: true, message: 'Logout successful' });
            }
          });
    });

app.route("/home")
    .get((req, res) => {
        console.log(req.headers);

    })


app.listen(process.env.PORT || 3001, () => {
    console.log("Server is running!")
})