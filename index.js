const express = require('express');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const passport = require('passport');
const dotenv = require('dotenv');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const helmet = require('helmet');
const cors = require('cors');
dotenv.config();
const connectDB = require('./config/connectdb');
const User = require('./models/user.model');
const { verifyToken } = require('./middlewares/verifyToken');
const port = process.env.PORT || 4000;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(helmet());
app.use(morgan('combined'));
app.use(cors());
connectDB();
//save id to session
passport.serializeUser((user, done) => {
    done(null, user?.id);
});
//mount user to req
passport.deserializeUser((id, done) => {
    User.findById(id).then((user) => {
        done(null, user);
    });
});
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: '/auth/google/callback',
            passReqToCallback: true,
        },
        (request, accessToken, refreshToken, profile, done) => {
            // console.log(profile);
            if (profile.id) {
                User.findOne({ googleId: profile.id }).then((existingUser) => {
                    if (existingUser) {
                        return done(null, existingUser);
                    } else {
                        new User({
                            googleId: profile.id,
                            email: profile.emails[0].value,
                            name: profile.name.givenName + ' ' + profile.name.familyName,
                        })
                            .save()
                            .then((user) => done(null, user));
                    }
                });
            }
        },
    ),
);
//using server side
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: true },
        maxAge: 30 * 24 * 60 * 60 * 1000,
    }),
);
app.use(passport.initialize());
app.use(passport.session());
app.get(
    '/auth/google',
    passport.authenticate('google', {
        scope: ['profile', 'email'],
    }),
);
app.get('/auth/google/callback', passport.authenticate('google'), (req, res) => {
    // console.log(req.session);
    const accessToken = jwt.sign({ userId: req?.user?._id }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '5h',
    });
    const { password, ...info } = req?.user;
    return res.status(200).json({ user: info, accessToken });
});
app.get('/api/books', verifyToken, (req, res) => {
    const books = [
        {
            id: 1,
            name: 'De Men Phieu Luu Ky',
        },
        {
            id: 2,
            name: 'Truyen Kieu',
        },
    ];
    return res.status(200).json(books);
});
app.post('/auth/register', async (req, res) => {
    const { email } = req.body;
    try {
        const findUser = await User.findOne({ email: email });
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        if (findUser?.googleId) {
            if (!findUser?.password) {
                await User.updateOne(
                    {
                        email: email,
                    },
                    {
                        password: hashedPassword,
                    },
                    {
                        new: true,
                    },
                );
                return res.status(200).json({
                    message: 'Add password field successfully',
                });
            } else {
                return res.status(400).json({
                    message: 'Password field already exists',
                });
            }
        }
        if (!findUser) {
            const newUser = new User({
                email: email,
                password: hashedPassword,
            });
            const updatedUser = newUser.save();
            const { password, ...info } = updatedUser?._doc;
            return res.status(201).json(info);
        }
    } catch (error) {
        return res.status(500).json({
            message: error.message,
        });
    }
});
app.post('/auth/login', async (req, res) => {
    const { email } = req.body;
    try {
        const findUser = await User.findOne({ email: email });
        if (!findUser) {
            return res.status(404).json({
                message: 'User not found',
            });
        }
        if (findUser && !findUser.password) {
            return res.status(404).json({
                message: 'Password field does not exist',
            });
        }
        const isValidPassword = await bcrypt.compare(req.body.password, findUser.password);
        if (!isValidPassword) {
            return res.status(400).json({ message: 'Wrong password' });
        }
        const { password, ...info } = findUser?._doc;
        const accessToken = jwt.sign({ userId: findUser?._id }, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: '5h',
        });
        return res.json({ ...info, accessToken });
    } catch (error) {}
});
app.listen(port, () => {
    console.log('Server running on http://localhost:%d', port);
});
