import Express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose"
import session from "express-session";
import 'dotenv/config';
import cors from "cors";




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

passport.use(User.createStrategy());

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


app.post("/login", (req, res) =>{
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
                req.login(user, (err) => {
                    if (err) {
                        console.log(err);
                        res.status(401).json({ success: false, message: "Invalid credentials" });
                        //
                    } else {
                        //
                        console.log("Logged in successfully!");
                        res.json({ success: true, message: "Login successful" });
                    }
        
                    
                });
            }
        })(req, res);
    }

})

app.post("/register", async (req, res) => {
        if(req.isAuthenticated()){
            console.log("You are logged in");
        } else {
            console.log(req.body);
            try {
                const newUser = await User.register(new User({ username: req.body.username }), req.body.password);
                await passport.authenticate("local")(req, res, () => {
                    console.log("Sign Up Success");
                    res.json({ success: true, message: "Sign up success" });
                });
            } catch (err) {
                console.error(err);
                if (err.name === "UserExistsError") {
                    
                    console.log("Username already exists. Please choose another username.");
                    res.status(401).json({ success: false, message: "Invalid credentials" });
                }
                
            }
        }
       
    });

app.route("/logout")
    .get((req, res) => {
        req.logout(function(err) {
            if (err) console.log(err);
            else {
                console.log("Log out successfully");
                res.json({ success: true, message: 'Logout successful' });
            }
          });
    })

app.listen(process.env.PORT || 3001, () => {
    console.log("Server is running!")
})