// app.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { connectDB } = require('../config/db');

const authRoutes = require('../routes/auth');
const app = express();

app.use(express.json());

const FRONTEND = process.env.FRONTEND_URL || 'http://localhost:3000'; // set this in env
const ALLOWED_ORIGINS = [FRONTEND, 'http://127.0.0.1:3000']; // add any dev host variations

const corsOptions = {
    origin: (origin, callback) => {
        // allow curl/Postman (origin === undefined), allow explicitly listed origins otherwise
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        return callback(new Error('CORS policy: Origin not allowed'), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'], // request headers
    // no need to add Set-Cookie here
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(cookieParser());

// mount routes exactly as before
app.use('/api', authRoutes);
app.get('/api/health', (req, res) => res.json({ ok: true }));

// serve static files (Vercel will also serve /public)
app.use(express.static(path.join(__dirname, 'public')));

// server.js

const PORT = process.env.PORT || 3000;

async function start() {
    await connectDB();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
    console.info('app and db started successfuly')
}

// start only when executed directly (not when imported by /api/index.js)

start().catch(err => {
    console.error('Failed to start', err);
    process.exit(1);
});

module.exports = app;