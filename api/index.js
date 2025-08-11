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
app.use(cors());
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