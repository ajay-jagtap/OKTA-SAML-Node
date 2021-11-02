var passport = require('passport');
var SamlStrategy = require('passport-saml').Strategy;
var config = require('./config.json')[process.env.NODE_ENV || 'dev'];

//users array to hold
var users = [];

function findByEmail(email, fn) {
    for (var i = 0, len = users.length; i < len; i++) {
        var user = users[i];
        if (user.nameID === email) {
            return fn(null, user);
        }
    }
    return fn(null, null);
}

//   Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

passport.use(new SamlStrategy(
    {
        path: '/login/callback',
        entryPoint: config.auth.entryPoint,
        issuer: config.auth.issuer,
        cert: config.auth.cert
    },
    function (profile, done) {
        findByEmail(profile.nameID,
            function (err, user) {
                if (err) {
                    return done(err);
                }
                if (!user) {
                    users.push(profile);
                    return done(null, profile);
                }
                return done(null, user);
            });
    })
);

passport.protected = function protected(req, res, next) {
    console.log('Login Profile' + req.isAuthenticated());
    if (req.isAuthenticated()) {
        return next();
    }
    console.log('login please' + req.isAuthenticated());
    res.redirect('/login');
};

exports = module.exports = passport;