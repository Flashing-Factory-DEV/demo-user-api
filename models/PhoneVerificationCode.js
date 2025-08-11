// models/PhoneVerificationCode.js
const mongoose = require('mongoose');

const phoneVerificationCodeSchema = new mongoose.Schema({
  phone: { type: String, required: true, index: true },
  code: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // optional link to the user for extra safety
  purpose: { type: String, default: 'phone_verification' }, // e.g. 'phone_verification', 'change_phone'
  expiresAt: { type: Date, required: true, index: true },
  used: { type: Boolean, default: false },
  attempts: { type: Number, default: 0 } // optional: how many verification attempts have been tried
}, { timestamps: true });

// TTL: remove expired codes automatically
phoneVerificationCodeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('PhoneVerificationCode', phoneVerificationCodeSchema);
