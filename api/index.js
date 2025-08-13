// app.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { connectDB } = require('../config/db');

const authRoutes = require('../routes/auth');
const app = express();

const FRONTEND = process.env.FRONTEND_URL

app.use(express.json());
const corsOptions = {
    origin: (origin, callback) => {
        // origin is undefined for non-browser requests (curl, Postman) — allow those too
        callback(null, origin || true) // echo origin or allow non-browser
    },
    credentials: true, // allow Set-Cookie and Cookie
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}

app.use(cors(corsOptions))
app.options('*', cors(corsOptions)) // preflight handler
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