require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser'); // <-- Move this here
const { connectDB } = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();

app.use(express.json());
app.use(cors());
app.use(cookieParser());  // Now cookieParser is defined properly

const PORT = process.env.PORT || 4000;

app.use('/api', authRoutes);

app.get('/api/health', (req, res) => res.json({ ok: true }));

async function start() {
  await connectDB();
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

app.get('/docs', (req, res) => {
  res.type('html').sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

start();
