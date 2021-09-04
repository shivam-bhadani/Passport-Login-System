require('dotenv').config();
const express = require("express");
const app = express();
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const methodOverride = require('method-override');
const flash = require("express-flash");
const passport = require('passport');

const initPassport = require('./passport-config');
initPassport(passport, (email) => {
    return User.findOne({ email: email });
});


mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true
}).then(() => {
    console.log('Connected to database')
}).catch((err) => {
    console.log(err);
});

const User = require('./models/user');


app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(methodOverride('_method'))

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", checkNotAuthenticated, (req, res) => {
    res.render("index")
});

app.get('/secret', checkAuthenticated, (req, res) => {
    res.render('secret', { user: req.user });
})

app.get("/login", checkNotAuthenticated, (req, res) => {
    res.render('login');
});


app.post('/login', passport.authenticate('local', {
    successRedirect: '/secret',
    failureRedirect: '/login',
    failureFlash: true
}))


app.get("/register", checkNotAuthenticated, (req, res) => {
    res.render("register")
});



app.post('/register', async (req, res) => {

    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const user = new User({
            name,
            email,
            password: hashedPassword
        });
        await user.save();

        res.redirect('/login');

    } catch (error) {
        console.log(error);
        res.redirect('/register');
    }
});

app.delete('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
})


function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    else
        res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/secret');
    }
    else
        next();
}

app.listen(process.env.PORT || 4500, () => console.log("Listening to Port 4500"))
