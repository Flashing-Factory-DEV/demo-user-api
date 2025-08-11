// models/ChangeEmailRequest.js
const mongoose = require('mongoose');

const changeEmailSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    newEmail: { type: String, required: true, lowercase: true, trim: true },
    tokenOld: { type: String, required: true }, // code/token sent to old email
    tokenNew: { type: String, required: true }, // code/token sent to new email
    stage: { type: String, enum: ['await_old', 'await_new', 'done'], default: 'await_old' },
    expiresAt: { type: Date, required: true, index: true },
    used: { type: Boolean, default: false } // optional
}, { timestamps: true });

// TTL index automatically removes stale requests
changeEmailSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('ChangeEmailRequest', changeEmailSchema);
