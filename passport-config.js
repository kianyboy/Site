const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const mysql = require("mysql2");

function initialize(passport, connection) {
    const authenticateUser = async (email, password, done) => {
        try {
            // Zoek de gebruiker op in de database op basis van e-mail
            connection.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
                if (err) {
                    return done(err);
                }

                if (results.length === 0) {
                    return done(null, false, { message: "Email not found" });
                }

                const user = results[0];

                try {
                    if (await bcrypt.compare(password, user.password)) {
                        return done(null, user);
                    } else {
                        return done(null, false, { message: "Password Incorrect" });
                    }
                } catch (e) {
                    return done(e);
                }
            });
        } catch (e) {
            return done(e);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));

    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser((id, done) => {
        connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
            if (err) {
                return done(err);
            }
            return done(null, results[0]);
        });
    });
}

module.exports = initialize;
