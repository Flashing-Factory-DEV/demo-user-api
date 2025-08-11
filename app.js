// app.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const authRoutes = require('./routes/auth');
const app = express();

app.use(express.json());
app.use(cors());
app.use(cookieParser());

// mount routes exactly as before
app.use('/api', authRoutes);
app.get('/api/health', (req, res) => res.json({ ok: true }));

// serve static files (Vercel will also serve /public)
app.use(express.static(path.join(__dirname, 'public')));

module.exports = app;
