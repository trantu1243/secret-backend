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
import { BlobServiceClient } from "@azure/storage-blob";
import { v1 as uuidv1 } from "uuid";
import multer from "multer";
import fs from "fs";





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
    firstName: String,
    lastName:String,
    avatarImageUrl: {
        type: String,
        default: "https://trantu1243.blob.core.windows.net/avatar/defaultAvatar.png",
    },
    backgroundImageUrl: {
        type: String,
        default: "https://trantu1243.blob.core.windows.net/background/defaultBackground.png"
    },
    image:[String],
    yourPostId:[String],
    yourSecretId:[String],
    repostId:[String],
    followerId:[String],
    followingId:[String],
    like:[String],
    comment:[String],
});

const postSchema = new mongoose.Schema({
    userId: String,
    name: String,
    avatarUser: String,
    content: String,
    postDate:{
        type: Date,
        default: Date.now,
    },
    interactDate:{
        type: Date,
        default: Date.now,
    },
    image:String,
    like:[String],
    comment:[String],
    repost:[String],
});

const secretSchema = new mongoose.Schema({
    content: String,
    postDate:{
        type: Date,
        default: Date.now,
    },
    image:[String],
    like:[String],
    comment:[String],
    repost:[String],
});

const commentSchema = new mongoose.Schema({
    userId:String,
    PostId: String,
    commentId: String,
    content:String,
    commentDate:{
        type: Date,
        default: Date.now,
    }
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("post", postSchema);
const Secret = mongoose.model("secret", secretSchema);
const Comment = mongoose.model("comment", commentSchema);

// passport-local
passport.use(User.createStrategy());

// passport-jwt
const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRET_TOKEN,
}
passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  
    const result = await User.findById(jwt_payload.user.id); 
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


// Blob service client
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING;
if (!AZURE_STORAGE_CONNECTION_STRING) {
    throw Error('Azure Storage Connection string not found');
  }
  // Create the BlobServiceClient object with connection string
const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_STORAGE_CONNECTION_STRING);



const authenticateToken = (req, res, next) => {
  
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) { return next(err); }
        if (!user) {
            console.log("Login failed");
            return res.status(401).json({ message: 'Unauthorized' });
        }
        req.login(user, { session: false }, (loginErr) => {
            if (loginErr) {
                console.log("Login failed");
                return next(loginErr);
            }
            return next();
        });
    })(req, res, next);
  };


app.route("/login")
    .get( authenticateToken, (req, res) => {
        res.json(req.user);
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
                    const token = jwt.sign({ user: {id:user._id} }, process.env.SECRET_TOKEN, { expiresIn: '3h' });
                    console.log(user.id);
                    res.json({token: token,});
                    
                
                }
            })(req, res);
        }

})

app.post("/register", async (req, res) => {
        
        console.log(req.body);
        try {
            const newUser = await User.register(
                new User({ 
                    username: req.body.username,
                    firstName: req.body.firstName,
                    lastName: req.body.lastName
                }), 
                req.body.password
            );

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
                    const token = jwt.sign({ user: {id:user._id} }, process.env.SECRET_TOKEN, { expiresIn: '3d' });
                    console.log(user.id);
                    res.json({token: token,});
                
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

    });

app.route("/profile/:id")
    .get(async(req, res) => {
        try{
            const result = await User.findById(req.params.id);
            res.json(result);
        }
        catch (e){
            res.status(500).send(e);
        }
        
    });


// upload avatar and background image
const upload = multer({ dest: 'uploads/' });

app.post("/upload/avatar", authenticateToken ,upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file || !fs.existsSync(req.file.path)) {
            return res.status(400).send('Invalid file');
        }

        const blobName = `avatar-${uuidv1()}`;
        const stream = fs.createReadStream(req.file.path);
        const size = req.file.size;
        const containerClient = blobServiceClient.getContainerClient(process.env.AVATAR_CONTAINER_NAME);
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);

        const uploadBlobResponse = await blockBlobClient.uploadStream(stream, size, undefined, {
            blobHTTPHeaders: { blobContentType: req.file.mimetype },
        });
      
        const result = await User.findById(req.user.id);
        if (result){
            
            result.avatarImageUrl = blockBlobClient.url;
            await result.save();
        }
        else {console.log("not found")};
        
        fs.unlinkSync(req.file.path);

        res.status(200).send('Image uploaded successfully');
    } catch (error) {
        console.error('Error uploading image to Azure Storage', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post("/upload/background", authenticateToken ,upload.single("background"), async (req, res) => {
    try {
        if (!req.file || !fs.existsSync(req.file.path)) {
            return res.status(400).send('Invalid file');
        }

        const blobName = `background-${uuidv1()}`;
        const stream = fs.createReadStream(req.file.path);
        const size = req.file.size;
        const containerClient = blobServiceClient.getContainerClient(process.env.BACKGROUND_CONTAINER_NAME);
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);

        const uploadBlobResponse = await blockBlobClient.uploadStream(stream, size, undefined, {
            blobHTTPHeaders: { blobContentType: req.file.mimetype },
        });
    
        const result = await User.findById(req.user.id);
        if (result){ 
            result.backgroundImageUrl = blockBlobClient.url;
            await result.save();
        }
        else {console.log("not found")};
        
        fs.unlinkSync(req.file.path);

        res.status(200).send('Image uploaded successfully');
    } catch (error) {
        console.error('Error uploading image to Azure Storage', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post("/upload/post", authenticateToken, upload.single("image"), async (req, res) =>{
    try{
       
        const newPost = new Post({
            userId: req.user._id,
            name: `${req.user.firstName + " " + req.user.lastName}`,
            avatarUser: req.user.avatarImageUrl,

        });


        if(req.body.text){
            newPost.content = req.body.text;
        }
        if (req.file && req.file.path){
            const blobName = `post-image-${uuidv1()}`;
            const stream = fs.createReadStream(req.file.path);
            const size = req.file.size;
            const containerClient = blobServiceClient.getContainerClient(process.env.POST_IMAGE_NAME);
            const blockBlobClient = containerClient.getBlockBlobClient(blobName);

            const uploadBlobResponse = await blockBlobClient.uploadStream(stream, size, undefined, {
                blobHTTPHeaders: { blobContentType: req.file.mimetype },
            });
            if (uploadBlobResponse){
                newPost.image = blockBlobClient.url;
            }

            fs.unlinkSync(req.file.path);
        }

        console.log(newPost);
        newPost.save();

        req.user.yourPostId.unshift(newPost._id);
        req.user.save();

        
        res.status(200).send("post uploaded successfully!");

    }
    catch (e) {
        console.error('Error uploading image to Azure Storage', e);
        res.status(500).send('Internal Server Error');
    }
})

app.route("/post/:id")
    .get(async(req, res) => {
        try{
            const result = await Post.findById(req.params.id);
            res.json(result);
        }
        catch (e){
            res.status(500).send(e);
            console.log(e);
        }
        
    });

app.post("/profile/follow", authenticateToken, async (req,res)=>{
    try{
        const user = await User.findById(req.body.id);
        if (!user.followerId.includes(req.user._id)){
            user.followerId.push(req.user._id);
            user.save();

            req.user.followingId.push(user._id);
            req.user.save();
        }
        
        
        res.status(200).send("Follow successfully");
    }
    catch (e){
        console.log(e);
        res.status(500).send("Failed");
    }
});

app.post("/profile/cancelFollow", authenticateToken, async (req,res)=>{
    try{
        const user = await User.findById(req.body.id);

        user.followerId = user.followerId.filter(item => item !== String(req.user._id));
        user.save();

        req.user.followingId = req.user.followingId.filter(item => item !== String(user._id));
        req.user.save();
        res.status(200).send("Cancel follow successfully");
    }
    catch(e){
        console.log(e);
        res.status(500).send("Failed");
    }
});


const port = process.env.PORT || 3001;
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
})