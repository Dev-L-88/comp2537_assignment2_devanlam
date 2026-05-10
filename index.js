require('dotenv').config();
const express = require("express");
const session = require("express-session");
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const atlas_url = `mongodb+srv://vibinboi1234:Dln0801@cluster0.jpsxpkk.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(atlas_url);
const userCollection = client.db(mongodb_database).collection('users');

const mongoStore = MongoStore.create({
    mongoUrl: atlas_url,
    collectionName: 'sessions',
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
        maxAge: 3600000 
    }
}));

// 1. Home Page
app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        // Not logged in
        res.send(`
            <a href='/signup'><button>Sign up</button></a>
            <a href='/login'><button>Log in</button></a>
        `);
    } else {
        // Logged in
        res.send(`
            Hello, ${req.session.name}!
            <br>
            <a href='/members'><button>Go to Members Area</button></a>
            <a href='/logout'><button>Logout</button></a>
        `);
    }
});

// 2. Sign up Page
app.get('/signup', (req, res) => {
    res.send(`
        <h2>Create User </h2>
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='name'><br>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
        `)
});

// Try again sign up 
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
        res.send(`Error: ${validationResult.error.details[0].message}. <br> <a href='/signup'>Try again</a>`);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
    req.session.authenticated = true;
    req.session.name = name;
    res.redirect('/members');
});

// 3. Login page
app.get('/login', (req, res) => {
    res.send(`
        <h2>Log in</h2>
        <form action='/loginSubmit' method='post'>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

// Try again login 
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
        res.redirect('/login');
        return;
    }

    const user = await userCollection.findOne({ email: email });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.authenticated = true;
        req.session.name = user.name;
        res.redirect('/members');
    } else {
        res.send("Invalid email/password combination. <br> <a href='/login'>Try again</a>");
    }
});

// 4. Members Area
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    
    const randomImage = Math.floor(Math.random() * 3) + 1;
    res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src='/img${randomImage}.jpg' style='width:250px;'/>
        <br>
        <a href='/logout'><button>Sign out</button></a>
    `);
});

// 5. Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

client.connect().then(() => {
    console.log("Successfully connected to MongoDB");
}).catch(err => {
    console.error("MongoDB connection error:", err);
});

// 8. 404 Error
app.get("/:universal", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
});