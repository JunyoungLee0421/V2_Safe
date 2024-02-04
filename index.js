require('./utils');

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;


const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');
const success = db_utils.printMySQLVersion();

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)


/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.7uvzogm.mongodb.net/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.render("authindex", { name: req.session.username });
    } else {
        res.render("index");
    }
});

app.get('/about', (req, res) => {
    var color = req.query.color;
    if (!color) {
        color = "black";
    }

    res.render("about", { color: color });
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    res.render("contact", { missing: missingEmail });
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", { email: email });
    }
});

app.get('/createTables', async (req, res) => {

    const create_tables = include('database/create_tables');

    var success = create_tables.createTables();
    if (success) {
        res.render("successMessage", { message: "Created tables." });
    }
    else {
        res.render("errorMessage", { error: "Failed to create tables." });
    }
});


app.get('/signup', (req, res) => {
    var missingusername = req.query.missingusername;
    var missingpassword = req.query.missingpassword;
    res.render("signup", {
        missingusername: missingusername,
        missingpassword: missingpassword
    })
});

app.get('/login', (req, res) => {
    var badlogin = req.query.badlogin;
    var missingusername = req.query.missingusername;
    var missingpassword = req.query.missingpassword;
    res.render("login", {
        missingusername: missingusername,
        missingpassword: missingpassword,
        badlogin: badlogin
    });
});

app.post('/signup', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    var hashedPassword = bcrypt.hashSync(password, saltRounds);

    if (!username) {
        res.redirect('signup?missingusername=1')
    } else if (!password) {
        res.redirect('signup?missingpassword=1')
    }

    var success = await db_users.createUser({ user: username, hashedPassword: hashedPassword });

    if (success) {
        var results = await db_users.getUsers();
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        // res.render("members", { users: results });
    }
    else {
        res.render("errorMessage", { error: "Failed to create user." });
    }

});

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        randomCat = Math.floor(Math.random() * 3) + 1;
        res.render("members", {
            username: req.session.username,
            cat_photo: `cat${randomCat}`
        });
    } else {
        res.redirect("/");
    }
});

app.post('/login', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    if (!username) {
        res.redirect('login?missingusername=1')
        return
    } else if (!password) {
        res.redirect('login?missingpassword=1')
        return
    }

    var results = await db_users.getUser({ user: username, hashedPassword: password });

    if (results) {
        if (results.length == 1) { //there should only be 1 user in the db that matches
            if (bcrypt.compareSync(password, results[0].password)) {
                req.session.authenticated = true;
                req.session.username = username;
                req.session.cookie.maxAge = expireTime;

                res.redirect('/members');
                return;
            }
            else {
                res.redirect("login?badlogin=1");
                return
                // console.log("invalid password");
            }
        }
        else {
            console.log('invalid number of users matched: ' + results.length + " (expected 1).");
            res.redirect('login?badlogin=1');
            return;
        }
    }

    console.log('user not found');
    //user and password combination not found
    res.redirect("/login");
});

app.post('/logout', async (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (!isValidSession(req)) {
        req.session.destroy();
        res.redirect('/login');
        return;
    }
    else {
        next();
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not Authorized" });
        return;
    }
    else {
        next();
    }
}

app.use('/loggedin', sessionValidation);
app.use('/loggedin/admin', adminAuthorization);

app.get('/loggedin', (req, res) => {
    res.render("loggedin");
});

app.get('/loggedin/info', (req, res) => {
    res.render("loggedin-info");
});

app.get('/loggedin/admin', (req, res) => {
    res.render("admin");
});

app.get('/cat/:id', (req, res) => {
    var cat = req.params.id;

    res.render("cat", { cat: cat });
});


app.get('/api', (req, res) => {
    var user = req.session.user;
    console.log("api hit ");

    var jsonResponse = {
        success: false,
        data: null,
        date: new Date()
    };


    if (!isValidSession(req)) {
        jsonResponse.success = false;
        res.status(401);  //401 == bad user
        res.json(jsonResponse);
        return;
    }

    if (typeof id === 'undefined') {
        jsonResponse.success = true;
        if (user_type === "admin") {
            jsonResponse.data = ["A", "B", "C", "D"];
        }
        else {
            jsonResponse.data = ["A", "B"];
        }
    }
    else {
        if (!isAdmin(req)) {
            jsonResponse.success = false;
            res.status(403);  //403 == good user, but, user should not have access
            res.json(jsonResponse);
            return;
        }
        jsonResponse.success = true;
        jsonResponse.data = [id + " - details"];
    }

    res.json(jsonResponse);

});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 