// config/db.js
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGODB_URI;

if (!MONGO_URI) {
  throw new Error('MONGO_URI is required in env');
}

let cached = global.__mongo; // reuse across lambda invocations

async function connectDB() {
  if (cached && cached.conn) {
    return cached.conn;
  }

  if (!cached) cached = global.__mongo = { conn: null, promise: null };

  if (!cached.promise) {
    cached.promise = mongoose.connect(MONGO_URI, {
      // mongoose options you use
    }).then(m => m.connection);
  }

  cached.conn = await cached.promise;
  return cached.conn;
}

module.exports = { connectDB };
