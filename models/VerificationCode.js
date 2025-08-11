// models/VerificationCode.js
const mongoose = require('mongoose');

const codeSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true, index: true },
  code: { type: String, required: true },
  purpose: { type: String, default: 'email_verification' }, // e.g. 'email_verification', 'change_email_old', etc
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // optional link
  expiresAt: { type: Date, required: true, index: true },
  used: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// TTL index: document removed when expiresAt passes
codeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('VerificationCode', codeSchema);
