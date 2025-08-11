// models/PasswordReset.js
const mongoose = require('mongoose');

const passwordResetSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    token: { type: String, required: true }, // PRODUCTION: store hash of token instead of raw token
    purpose: { type: String, default: 'password_reset' }, // or 'delete_account' reuse
    expiresAt: { type: Date, required: true, index: true },
    used: { type: Boolean, default: false }
}, { timestamps: true });

// TTL index
passwordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('PasswordReset', passwordResetSchema);
