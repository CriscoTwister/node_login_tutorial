const express = require('express');
const app = express();
const { pool } = require("./dbConfig"); 
const bcryptjs = require('bcryptjs');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');

// importing configuration for passport
const initializePassport = require("./passportConfig")

// initializing passport for user authentication
initializePassport(passport);

// set port, env or 4000 if not specified
const PORT = process.env.PORT || 4000;

// allowing embedded javascript to be used
app.set("view engine", "ejs");

// for parsing incoming requests with URL encoded payloads.
// this middleware parses the data and populates the req.body with
// key-value pairs. 
app.use(express.urlencoded({ extended: false }))

// session settings 
app.use(
    session({
         // Key we want to keep secret which will encrypt all of our information
        secret: 'secret',
        // Should we resave our session variables if nothing has changes which we dont
        resave: false,
        // Save empty value if there is no vaue which we do not want to do
        saveUninitialized: false,
}))

// start passport, authentication middleware that authenticates requests
app.use(passport.initialize());
// passport.session() acts as a middleware to alter the req object and change the 'user' value that is 
// currently the session id (from the client cookie) into the true deserialized user object.
app.use(passport.session());

// Flash is an extension of connect-flash with the ability to define a flash message and render it without redirecting the request.
app.use(flash());

// render index as a response when root is requested.
app.get('/', (req, res) => {
  res.render('index');
});

// check if user is authenticated, if so redirected to dashboard. 
// otherwise, render register page. 
app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render('register');
});

// check if user is authenticated, if so redirect to dashboard. 
// otherwise, render login page. 
app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render('login');
});

// logout routing. send a success message after logout, then go to login. 
app.get('/users/logout', (req, res) => {
    req.logOut(function (err) {
        if (err) { return next(err);}
        req.flash('success_msg', "you have logged out");
        res.redirect('/users/login');
    });

})

// dashboard routing. check if they're NOT authenticated. send them to login if not authenticated.
// otherwise, render dashbaord and display username. 
app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
    res.render('dashboard', {user: req.user.name});
});

// register routing. async because of hashedpassword using await. 
// register users with name, email, password, and password2 to verify password. 
// succesful registration sends data to 'users' table and redirects to login. 
app.post('/users/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;
    console.log({
        name, 
        email,
        password,
        password2
    });

    let errors = [];
    
    // check if every field is populated. 
    if (!name || !email || !password || !password2){
        errors.push({message: "please enter all fields!!"})
    }

    // check if password length is 6 or more
    if(password.length < 6){
        errors.push({message: "Password should be at least 6 characters"});
    }

    // make sure passwords match
    if (password != password2) {
        errors.push({message: "passwords do not match!!"})
    }

    // render errors if there are any, otherwise hash password and send it to users table
    if (errors.length > 0) {
        res.render("register", {errors})
    } else {
        // Form validation has passed
        
        // hashing password for secure storage via bcryptjs
        let hashedPassword = await bcryptjs.hash(password, 10);
        console.log(hashedPassword);

        // pool is our db config so we can connect to the users table.
        // see if email is already registered. if it's registered, render the error.
        // if not registered, store new user data in users table, flash success message, redirect to login. 
        pool.query(
            `SELECT * FROM users
            WHERE email = $1`, [email], 
            (err, results) => {
                if (err){
                    throw err;
                }
                console.log('reaches here')
                console.log(results.rows);

                if (results.rows.length > 0) {
                    errors.push({message: "email already registered!!"});
                    res.render('register', { errors });
                }  else {
                    pool.query(
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`, [name, email, hashedPassword], 
                        (err, results) => {
                            if (err) {
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash('success_msg', "You are now registered, please log in");
                            res.redirect("/users/login");
                        }
                    )
                }
            }
        )
    }
});

// using passportConfig, check if login data is valid. redirect to dashboard if it is.
// if failure, it'll send an error message as designated in passportConfig authenticateUser.   
app.post(
    '/users/login', 
    passport.authenticate('local', {
        successRedirect: "/users/dashboard",
        failureRedirect: '/users/login',
        failureFlash: true
    })
);

// check if authenticated. req.isAuthenticated is passport middlware. 
// if authenticated, redirect to dashboard. otherwise, go to the next middleware. 
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return res.redirect('/users/dashboard');
    }
    next();
}

// check if NOT authenticated. req.isAuthenticated is passport middlware. 
// if authenticated, go to next middlware. otherwise, redirect to login. 
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return next();;
    }

    res.redirect("/users/login");
}

// start the serveer and log the port it is running on. 
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});