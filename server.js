require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static('uploads'));

// Set view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// MongoDB Atlas Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        collectionName: 'sessions'
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1-day expiration
}));

// File Upload Configuration (Multer)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

// User Schema
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    role: { type: String, default: 'user' }, // 'admin' or 'user'
    profilePicture: { type: String, default: '/default-profile.png' }
});

const User = mongoose.model('User', userSchema);

// Middleware for authentication
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Middleware for authentication (Ensures user is logged in)
const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Middleware for admin access
const requireAdmin = async (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    try {
        const user = await User.findById(req.session.userId);
        if (!user || user.role !== 'admin') {
            return res.status(403).send('Access denied.');
        }
        next();
    } catch (err) {
        console.error('Error checking admin role:', err);
        res.status(500).send('Internal Server Error');
    }
};

// Home Route - Requires Login
app.get('/', requireAuth, async (req, res) => {
    const user = await User.findById(req.session.userId);
    res.render('index', { user });
});

// Admin Dashboard - Only accessible to admins
app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const users = await User.find(); // Fetch all users
        const adminUser = await User.findById(req.session.userId); // Get logged-in admin info
        res.render('admin', { users, user: adminUser }); // Pass 'user' to EJS
    } catch (err) {
        console.error('Error fetching admin data:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Registration Routes
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', upload.single('profilePicture'), async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const profilePicture = req.file ? `${req.file.filename}` : '/default-profile.png';

        const newUser = new User({ name, email, password: hashedPassword, profilePicture });
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        res.status(500).send('Error registering user');
    }
});

// Login Routes
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send('Invalid email or password');
        }

        req.session.userId = user._id;
        res.redirect('/');
    } catch (err) {
        res.status(500).send('Error logging in');
    }
});

// Profile Routes
app.get('/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) return res.status(404).send('User not found');

        res.render('profile', { user });
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/profile/update', requireAuth, upload.single('profilePicture'), async (req, res) => {
    try {
        const { name, email } = req.body;
        let updateData = { name, email };

        if (req.file) {
            const user = await User.findById(req.session.userId);
            if (user.profilePicture !== '/default-profile.png') {
                fs.unlinkSync(`./uploads/${user.profilePicture.split('/').pop()}`);
            }
            updateData.profilePicture = `/uploads/${req.file.filename}`;
        }

        await User.findByIdAndUpdate(req.session.userId, updateData, { new: true });
        res.redirect('/profile');
    } catch (err) {
        console.error('Error updating profile:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/profile/delete', requireLogin, async (req, res) => {
    try {
        const userId = req.session.userId;

        // Check if user exists before deleting
        const user = await User.findById(userId);
        if (!user) return res.status(404).send('User not found');

        // Delete the user account
        await User.findByIdAndDelete(userId);

        // Destroy session after deleting account
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).send('Error logging out after account deletion');
            }
            res.redirect('/login'); // Redirect to login after deleting
        });
    } catch (err) {
        console.error('Error deleting account:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
