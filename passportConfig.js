const LocalStrategy = require("passport-local").Strategy;
const { authenticate } = require("passport");
const { pool } = require('./dbConfig');
const bcryptjs = require('bcryptjs');

// initialize and setup passport authentication
function initialize (passport) {

    // function to authenticate user. email and password matching. 
    // search for email in users table, grab the first row (there should be only 1?),
    // then use bcrpytjs to compare the submitted password to the hashed one in the table. 
    // if password doesn't match or email isn't in table, send an appropriate message. 
    const authenticateUser = (email, password, done) => {

        pool.query(
            `SELECT * FROM users WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
            console.log(results.rows);

            if (results.rows.length > 0) {
                const user = results.rows[0];

                bcryptjs.compare(password, user.password, (err, isMatch) => {
                    if(err) {
                        throw err
                    }

                    if (isMatch) {
                        return done(null, user);
                    } else {
                        // password is wrong
                        return done(null, false, {message: "Password is not correct"});
                    }
                }); 
            } else {
                // no user in table
                return done(null, false, {message: "email is not registered"});
            }
            }
        )
    }
    // set up local strategy, which authenticates users using a username and password. 
    passport.use(
        new LocalStrategy(
            {
                usernameField: "email",
                passwordField: "password",
            },
            authenticateUser
        )
    )

    // Stores user details inside session. serializeUser determines which data of the user
    // object should be stored in the session. The result of the serializeUser method is attached
    // to the session as req.session.passport.user = {}. Here for instance, it would be (as we provide
    // the user id as the key) req.session.passport.user = {id: 'xyz'}
    passport.serializeUser((user, done) => done(null, user.id));

    // In deserializeUser that key is matched with the in memory array / database or any data resource.
    // The fetched object is attached to the request object as req.user
    passport.deserializeUser((id, done) => {
        pool.query(
            `SELECT * FROM users WHERE id = $1`, [id], (err,results) => {
                if (err){
                    throw err;
                }
                return done(null, results.rows[0]);
            }
        )
    })
}


module.exports = initialize;