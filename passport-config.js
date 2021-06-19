const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const User = require('./models/user');

function initPassport(passport, getUserByEmail) {

    const authenticateUser = async (email, password, done) => {
        const user = await getUserByEmail(email);
        if (user == null) {
            return done(null, false, { message: "No user registered with this email" })
        }

        try {

            const match = await bcrypt.compare(password, user.password);
            if (match) {
                return done(null, user);
            }
            else {
                return done(null, false, { message: "Wrong email or password" });
            }

        } catch (error) {
            return done(error);
        }
    }

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        User.findById(id, (err, user) => {
            done(err, user);
        });
    });
}

module.exports = initPassport;