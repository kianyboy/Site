if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
}

// Importing installed libraries
const express = require("express");
const app = express();
const path = require('path');
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const mysql = require("mysql2");
const methodOverride = require("method-override");
const nodemailer = require("nodemailer"); // Nodemailer voor e-mails

// Initialize passport configuration
const initializePassport = require("./passport-config");
initializePassport(
    passport,
    email => findUserByEmail(email),
    id => findUserById(id)
);

// MySQL database connection (DigitalOcean)
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: {
        rejectUnauthorized: false
    }
});

connection.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to the MySQL database on DigitalOcean.');
});

// Nodemailer setup voor e-mailverificatie
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Utility functions to find user
function findUserByEmail(email) {
    return new Promise((resolve, reject) => {
        connection.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) return reject(err);
            resolve(results[0]);
        });
    });
}

function findUserById(id) {
    return new Promise((resolve, reject) => {
        connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
            if (err) return reject(err);
            resolve(results[0]);
        });
    });
}

// Routes
app.get('/', (req, res) => {
    res.render("index.ejs");
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render("login.ejs");
});

app.post("/login", checkNotAuthenticated, passport.authenticate("local", {
    successRedirect: "/Dashboard",
    failureRedirect: "/login",
    failureFlash: true
}));

app.get('/signup', checkNotAuthenticated, (req, res) => {
    res.render("signup.ejs");
});

app.post("/signup", checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const { name, username, email } = req.body;

        // Verificatie token genereren
        const verificationToken = Math.random().toString(36).substr(2, 12);

        const query = 'INSERT INTO users (name, username, email, password, verificationToken, isVerified) VALUES (?, ?, ?, ?, ?, ?)';
        connection.query(query, [name, username, email, hashedPassword, verificationToken, false], (err, result) => {
            if (err) {
                console.error('Error inserting user into database:', err);
                return res.status(500).send('Internal server error');
            }

            // Verificatie e-mail verzenden
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Account Verification',
                text: `Hello ${name},\n\nPlease verify your account by clicking the link: \nhttp://${req.headers.host}/verify-email?token=${verificationToken}\n\nThank you!\n`
            };

            transporter.sendMail(mailOptions, (err, info) => {
                if (err) {
                    console.error('Error sending verification email:', err);
                    return res.status(500).send('Error sending verification email');
                }
                console.log('Verification email sent: ' + info.response);
                res.redirect("/login");
            });
        });
    } catch (e) {
        console.error(e);
        res.status(500).send("Error creating user");
    }
});

app.get('/verify-email', async (req, res) => {
    const { token } = req.query;

    const query = 'SELECT * FROM users WHERE verificationToken = ?';
    connection.query(query, [token], (err, results) => {
        if (err) {
            console.error('Error verifying email:', err);
            return res.status(500).send('Internal server error');
        }

        if (results.length === 0) {
            return res.status(400).send('Invalid or expired verification token');
        }

        const user = results[0];

        connection.query('UPDATE users SET isVerified = true, verificationToken = null WHERE id = ?', [user.id], (err) => {
            if (err) {
                console.error('Error updating user verification status:', err);
                return res.status(500).send('Internal server error');
            }
            res.send('Email verified! You can now log in.');
        });
    });
});

app.get('/learnmore', (req, res) => {
    res.render("Learnmore.ejs");
});

app.get('/Documentation', (req, res) => {
    res.render("Documentation.ejs");
});

app.get('/Dashboard', checkAuthenticated, (req, res) => {
    if (!req.user.isVerified) {
        req.flash('error', 'Please verify your email before accessing the dashboard.');
        return res.redirect('/login');
    }
    res.render("Dashboard.ejs", { name: req.user.name });
});

// Logout route
app.delete("/logout", (req, res) => {
    req.logOut();
    res.redirect("/login");
});

// Catch-all route for unknown routes
app.use((req, res) => {
    res.status(404).send("Page not found");
});

// Authentication middlewares
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/Dashboard");
    }
    next();
}

// Start server
const port = process.env.PORT || 5500;
app.listen(port, () => {
    console.log(`Server started on port ${port}`);
});
