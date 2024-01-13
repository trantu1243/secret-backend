import Express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose"
import 'dotenv/config';
import cors from "cors";
import jwt from "jsonwebtoken";
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { BlobServiceClient } from "@azure/storage-blob";
import { v1 as uuidv1 } from "uuid";
import multer from "multer";
import fs from "fs";
import http from "http";
import {Server} from "socket.io";


const app = Express();
const sever = http.createServer(app);
const io = new Server(sever);

app.use(bodyParser.urlencoded({extended:true}));
app.use(bodyParser.json());

app.use(cors());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});


app.use(passport.initialize());

mongoose.connect("mongodb+srv://trantu1242003:TU1242kkk3@cluster0.6wvbq5t.mongodb.net/SecretApp?retryWrites=true&w=majority");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    firstName: String,
    lastName:String,
    name: String,
    avatarImageUrl: {
        type: String,
        default: "https://trantu1243.blob.core.windows.net/avatar/defaultAvatar.png",
    },
    backgroundImageUrl: {
        type: String,
        default: "https://trantu1243.blob.core.windows.net/background/defaultBackground.png"
    },
    image:[String],
    yourPostId:[{type: mongoose.Schema.Types.ObjectId}],
    yourSecretId:[{type: mongoose.Schema.Types.ObjectId}],
    repostId:[{type: mongoose.Schema.Types.ObjectId}],
    followerId:[{type: mongoose.Schema.Types.ObjectId}],
    followingId:[{type: mongoose.Schema.Types.ObjectId}],
    like:[{type: mongoose.Schema.Types.ObjectId}],
    comment:[{type: mongoose.Schema.Types.ObjectId}],
    notification:[{
        postId: {type:mongoose.Schema.Types.ObjectId},
        name: String,
        content: String,
        avatarImageUrl: String,
        date: {type:Date},
    }],
    checkNotification:{
        type: Number,
        default:0,
    }
});

const postSchema = new mongoose.Schema({
    userId: {type: mongoose.Schema.Types.ObjectId},
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
    like:[{type: mongoose.Schema.Types.ObjectId}],
    comment:[{type: mongoose.Schema.Types.ObjectId}],
    repost:[{type: mongoose.Schema.Types.ObjectId}],
    secret:{type:Boolean, default:false},
});

const secretSchema = new mongoose.Schema({
    name:{type:String, default:"Anonymous user"},
    avatarUser:{type: String, default:"https://trantu1243.blob.core.windows.net/loadimage-11ee-814b-45e4577e52de/Screenshot 2024-01-13 225329.png"},
    content: String,
    postDate:{
        type: Date,
        default: Date.now,
    },
    image:[String],
    like:[{type: mongoose.Schema.Types.ObjectId}],
    comment:[{type: mongoose.Schema.Types.ObjectId}],
    repost:[{type: mongoose.Schema.Types.ObjectId}],
});

const commentSchema = new mongoose.Schema({
    userId:{type: mongoose.Schema.Types.ObjectId},
    postId: {type: mongoose.Schema.Types.ObjectId},
    name: String,
    avatarImageUrl: String,
    like: [{type: mongoose.Schema.Types.ObjectId}],
    comment: [{type: mongoose.Schema.Types.ObjectId}],
    content:String,
    commentDate:{
        type: Date,
        default: Date.now,
    }
});

userSchema.path("followingId").ref("User");
userSchema.path("yourPostId").ref("Post");
postSchema.path("userId").ref("User");

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
    cb(null, user.id);
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


// socket

io.on('connection', (socket) => {
    console.log('Client connected');
  
    // handle disconnect event
    socket.on('disconnect', () => {
      console.log('Client disconnected');
    });
});


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
        res.json({
            _id: req.user._id,
            firstName: req.user.firstName,
            lastName: req.user.lastName,
            name: req.user.name,
            avatarImageUrl: req.user.avatarImageUrl,
            backgroundImageUrl: req.user.backgroundImageUrl,
            image: req.user.image,
            yourPostId: req.user.yourPostId,
            yourSecretId: req.user.yourSecretId,
            repostId: req.user.repostId,
            followerId: req.user.followerId,
            followingId: req.user.followingId,
            like: req.user.like,
            comment: req.user.comment,
            notification: req.user.notification,
            checkNotification: req.user.checkNotification,
        });
    })

    .post((req, res) =>{
        console.log(req.body);
        if(req.isAuthenticated()){ 
            console.log("You are logged in");
        }
        else {
            passport.authenticate("local", { session: false },(err, user, info) => {
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
                    lastName: req.body.lastName,
                    name: `${req.body.firstName + " " + req.body.lastName}`,
                }), 
                req.body.password
            );

            console.log(req.body);
            passport.authenticate("local", { session: false },(err, user, info) => {
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


app.route("/home")
    .get((req, res) => {
        console.log(req.headers);

    });

app.route("/profile/:id")
    .get(async(req, res) => {
        try{
            const result = await User.findById(req.params.id);
            res.json({
                _id: result._id,
                firstName: result.firstName,
                lastName: result.lastName,
                name: result.name,
                avatarImageUrl: result.avatarImageUrl,
                backgroundImageUrl: result.backgroundImageUrl,
                image: result.image,
                yourPostId: result.yourPostId,
                repostId: result.repostId,
                followerId: result.followerId,
                followingId: result.followingId,
                like: result.like,
                comment: result.comment,
            });
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

        newPost.save();

        req.user.yourPostId.unshift(newPost._id);
        req.user.save();

        res.status(200).json({postId:String(newPost._id)});

        req.user.followerId.map(async (objId)=>{
            const user = await User.findById(String(objId));
            user.notification.unshift({
                postId: newPost._id,
                name: req.user.name,
                content:" posted one post",
                avatarImageUrl: req.user.avatarImageUrl,
                date: Date.now(),
            });
            
            user.checkNotification++;
            user.save();
        });
        
  
    }
    catch (e) {
        console.error('Error uploading image to Azure Storage', e);
        res.status(500).send('Internal Server Error');
    }
});

// upload secret

app.post("/upload/secret", authenticateToken, upload.single("image"), async (req, res) =>{
    try{
       
        const newPost = new Post({
            userId: req.user._id,
            name: "Anonymous user",
            avatarUser: "https://trantu1243.blob.core.windows.net/secret-11ee-814b-45e4577e52de/Screenshot-2024-01-13-225329.png",
            secret: true,
        });

        if(req.body.text){
            newPost.content = req.body.text;
        }
        if (req.file && req.file.path){
            const blobName = `post-image-${uuidv1()}`;
            const stream = fs.createReadStream(req.file.path);
            const size = req.file.size;
            const containerClient = blobServiceClient.getContainerClient(process.env.SECRET_IMAGE_NAME);
            const blockBlobClient = containerClient.getBlockBlobClient(blobName);

            const uploadBlobResponse = await blockBlobClient.uploadStream(stream, size, undefined, {
                blobHTTPHeaders: { blobContentType: req.file.mimetype },
            });
            if (uploadBlobResponse){
                newPost.image = blockBlobClient.url;
            }

            fs.unlinkSync(req.file.path);
        }

        newPost.save();
        console.log(newPost);

        req.user.yourSecretId.unshift(newPost._id);
        req.user.save();

        res.status(200).json({postId:String(newPost._id)});

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
            if (!result.secret) res.json(result);
            else res.json({
                _id: result._id,
                name: result.name,
                avatarUser: result.avatarUser,
                content: result.content,
                postDate: result.postDate,
                interactDate: result.interactDate,
                image: result.image,
                like: result.like,
                comment: result.comment,
                repost: result.repost,
                secret: result.secret,
            });
            
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

        user.followerId = user.followerId.filter(item => String(item) !== String(req.user._id));
        user.save();

        req.user.followingId = req.user.followingId.filter(item => String(item) !== String(user._id));
        req.user.save();
        res.status(200).send("Cancel follow successfully");
    }
    catch(e){
        console.log(e);
        res.status(500).send("Failed");
    }
});


app.get("/getposts", authenticateToken, async (req, res) =>{
    const skip = parseInt(req.query.skip, 10);
    try{
        const user = await User.findById(String(req.user._id));
        if (user.followingId.length>0){
            const result = await User.aggregate([
                {
                    $match: {_id:{$in: user.followingId}}
                },
                {
                    $project:{
                        yourPostId:1
                    }
                },
                {
                    $unwind:"$yourPostId"
                },
                {
                    $group:{
                        _id: null,
                        combinedFollow:{$push:"$yourPostId"}
                    }
                },
                {
                    $project:{
                        _id:0,
                        combinedFollow:1
                    }
                }
                
            ]);

            
            const posts = await Post.aggregate([
                {
                    $match:{_id:{$in: result[0].combinedFollow}}
                },
                {
                    $sort:{
                        interactDate:-1,
                    }
                },
                {
                    $project:{
                        _id:1,
                   
                    }
                },
                {
                    $group:{
                        _id: null,
                        ids:{$push:"$_id"}
                    }
                }
            ]);
        
            if (posts.length > 0){
                res.json({posts:posts[0].ids.slice(skip, skip+5)});
            } else{
                res.json({posts:[]});
            }
        } else {
            res.json({posts:[]});
        }
        
    }
    catch(e){
        console.log(e);
        res.status(500);
    }
});

app.get("/getSecret", authenticateToken, async (req, res) =>{
    const skip = parseInt(req.query.skip, 10);
    try{
            
        const posts = await Post.aggregate([
            {
                $match:{
                    $and:[
                        {userId:{$ne: req.user._id}},
                        {secret:true}
                    ]}
            },
            {
                $sort:{
                    interactDate:-1,
                }
            },
            {
                $project:{
                    _id:1,
                }
            },
            {
                $group:{
                    _id: null,
                    ids:{$push:"$_id"}
                }
            }
        ]);

    
        if (posts.length > 0){
            res.json({posts:posts[0].ids.slice(skip, skip+5)});
        } else{
            res.json({posts:[]});
        }
       
        
    }
    catch(e){
        console.log(e);
        res.status(500);
    }
});


app.get("/profilePosts", async (req,res)=>{
    try{
        const skip = parseInt(req.query.skip, 10);
        const result = await User.findById(req.query.id);
        const posts = result.yourPostId;
        // console.log(posts.slice(skip, skip+5));
        if (posts){
            
            res.json({posts:posts.slice(skip, skip+5)});
        }
        else{
            res.json({posts:[]});
        }
    }
    catch(e){
        console.log(e);
        res.status(500);
    }
    
});

app.get("/yourSecret", authenticateToken, async (req,res)=>{
    try{
        const skip = parseInt(req.query.skip, 10);
        if (req.user.yourSecretId){
            const posts = req.user.yourSecretId;
        
            if (posts){
                
                res.json({posts:posts.slice(skip, skip+5)});
            }
            else{
                res.json({posts:[]});
            }
        } else {
            res.json({posts:[]});
        }
        
    }
    catch(e){
        console.log(e);
        res.status(500);
    }
    
});

// get liked post

app.get("/profileLikedPosts", async (req,res)=>{
    try{
        const skip = parseInt(req.query.skip, 10);
        const result = await User.findById(req.query.id);
        const posts = result.like;
        // console.log(posts.slice(skip, skip+5));
        if (posts){
            
            res.json({posts:posts.slice(skip, skip+5)});
        }
        else{
            res.json({posts:[]});
        }
    }
    catch(e){
        console.log(e);
        res.status(500);
    }
    
});

app.patch("/post/like", authenticateToken, async(req, res)=>{
    try{
        const post = await Post.findById(req.body.id);
        
        if (!post.like.includes(req.user._id)){
            post.like.unshift(req.user._id);
            post.save();
   

            req.user.like.unshift(post._id);
            req.user.save();
        }
        res.status(200).send("success");
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.patch("/post/unlike", authenticateToken, async(req, res)=>{
    try{
        const post = await Post.findById(req.body.id);
        
        post.like = post.like.filter(item => String(item) !== String(req.user._id));
        post.save();
   
        req.user.like = req.user.like.filter(item => String(item) !== String(post._id));
        req.user.save();
        
        res.status(200).send("success");
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});

//get comments

app.get("/post/comments/:id", async (req, res)=>{
    try{
        const result = await Post.findById(req.params.id);
        if (result.comment) {
            res.status(200).json({commentId:result.comment});
        } else {
            res.status(200).json({commentId:[]});
        }
        
    }
    catch(e){
        console.log(e);
        res.status(500).send(e);
    }
})

// handle comment

app.get("/comment/:id", async(req, res)=>{
    try{
        const result = await Comment.findById(req.params.id);
        res.json(result);
        
    }
    catch (e){
        console.log(e);
        res.status(500).send(e);
    }
});

app.post("/comment", authenticateToken, async(req, res)=>{
    try{

        const post = await Post.findById(req.body.postId);
        const newComment = new Comment({
            postId: post._id,
            userId: req.user._id,
            name: `${req.user.firstName + " " + req.user.lastName}`,
            avatarImageUrl: req.user.avatarImageUrl,
            content: req.body.text,
        });
        newComment.save();
  

        post.comment.unshift(newComment._id);
        post.save();

        req.user.comment.unshift(newComment._id);
        req.user.save();

        res.status(200).send("success");

        const user = await User.findById(String(post.userId));
        user.notification.unshift({
            postId: post._id,
            name: req.user.name,
            content:" commented in your post",
            avatarImageUrl: req.user.avatarImageUrl,
            date: Date.now(),
        });

       
        user.checkNotification++;
        user.save();
    }
    catch (e){
        console.log(e);
        res.status(500).send(e);
    }
});

// like and unlike comment

app.patch("/comment/like", authenticateToken, async(req, res)=>{
    try{
        const comment = await Comment.findById(req.body.id);
        
        if (!comment.like.includes(req.user._id)){
            comment.like.unshift(req.user._id);
            comment.save();
   

            req.user.like.unshift(comment._id);
            req.user.save();
        }
        res.status(200).send("success");
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.patch("/comment/unlike", authenticateToken, async(req, res)=>{
    try{
        const comment = await Comment.findById(req.body.id);
        
        comment.like = comment.like.filter(item => String(item) !== String(req.user._id));
        comment.save();
   
        req.user.like = req.user.like.filter(item => String(item) !== String(comment._id));
        req.user.save();
        
        res.status(200).send("success");
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});


// handle repost

app.patch("/post/repost", authenticateToken, async(req, res)=>{
    try{
        const post = await Post.findById(req.body.id);
        
        if (!post.repost.includes(req.user._id)){
            post.repost.unshift(req.user._id);
            post.save();
   

            req.user.repostId.unshift(post._id);
            req.user.yourPostId.unshift(post._id);
            req.user.save();
        }
        res.status(200).send("success");
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.patch("/post/unrepost", authenticateToken, async(req, res)=>{
    try{
        const post = await Post.findById(req.body.id);
        
        post.repost = post.repost.filter(item => String(item) !== String(req.user._id));
        post.save();
   
        req.user.repostId = req.user.repostId.filter(item => String(item) !== String(post._id));
        req.user.yourPostId = req.user.yourPostId.filter(item => String(item) !== String(post._id));
        req.user.save();
        
        res.status(200).send("success");
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.patch("/edit/post", authenticateToken, upload.single("image"), async (req, res)=>{
    try{
        const post = await Post.findById(req.body.postId);
    
        if (req.body.text) {
            post.content = req.body.text;
        }
        else {
            post.content ="";
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
                post.image = blockBlobClient.url;
            }

            fs.unlinkSync(req.file.path);
        }

        post.save();

        res.status(200).send("edit successfully!");

    }
    catch(e){
        console.log(e);
        res.status(500).send('Internal Server Error');
    }
});

// delete post

app.put("/delete/post", authenticateToken, async (req, res) => {
    try{
        console.log(req.body);

        req.user.yourPostId = req.user.yourPostId.filter(item => String(item) !== req.body.id);
        req.user.save();
        
        await Post.findByIdAndDelete(req.body.id).then(() => {
            console.log("success");
            res.status(200).send("Delete successfully");
        }).catch(e => {
            console.log(e);
            res.status(500).send('Internal Server Error');
        });
    }
    catch (e){
        console.log(e);
        res.status(500).send('Internal Server Error');
    }
});

// edit comment

app.patch("/edit/comment", authenticateToken, async(req, res)=>{
    try{
        const comment = await Comment.findById(req.body.commentId);
        comment.content = req.body.text;
        comment.save();

        res.status(200).send("Success");
    }
    catch (e) {
        console.log(e);
        res.status(500).send(e);
    }
});

// delete comment
app.put("/delete/comment", authenticateToken, async (req, res)=>{
    try{
        console.log(req.body);
        req.user.comment = req.user.comment.filter((item)=>(String(item)!==req.body.commentId));
        req.user.save();

        const post = await Post.findById(req.body.postId);
        post.comment = post.comment.filter((item)=>(String(item)!==req.body.commentId));
        post.save();

        await Comment.findByIdAndDelete(req.body.commentId).then(() => {
            console.log("success");
            res.status(200).send("Delete successfully");
        }).catch(e => {
            console.log(e);
            res.status(500).send('Internal Server Error');
        });
        
    }
    catch (e){
        console.log(e);
        res.status(500).send('Internal Server Error');
    }
});

// get user list

app.get("/userList", authenticateToken, async (req, res) => {
    try{
        const result = await User.aggregate([
            {
                $match:{
                    $and:[
                        {_id:{$in: req.user.followingId}},
                        {_id:{$in: req.user.followerId}},
                    ]
                }
            },
            {
                $project:{
                    _id:1,
                    firstName:1,
                    lastName:1,
                    avatarImageUrl:1,
                }
            }   
        ]);
        
        res.json({userList:result});
    }
    catch (e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.get("/search/user", async (req, res)=>{
    try{
        const result = await User.aggregate([
            {
                $match:{
                    $or:[
                        { firstName: { $regex: new RegExp(req.query.name, 'i') } },
                        { lastName: { $regex: new RegExp(req.query.name, 'i') } },
                        { name: { $regex: new RegExp(req.query.name, 'i') } }
                    ]
                },
            },
            {
                $project:{
                    _id:1,
                    firstName:1,
                    lastName:1,
                    avatarImageUrl:1,
                }
            }
        ]);
        res.json({userList:result});
    }
    catch(e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.patch("/notification", authenticateToken, (req, res)=>{
    try{
        req.user.checkNotification = 0;
        req.user.save();
        res.send("Success");
    }
    catch (e){
        console.log(e);
        res.status(500).send("failed");
    }
});

app.get("/notification", authenticateToken, (req, res)=>{
    try{
        res.json(req.user.checkNotification);
    }
    catch (e){
        console.log(e);
        res.status(500).send("failed");
    }
});

const port = process.env.PORT || 3001;
sever.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
})