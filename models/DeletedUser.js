// models/DeletedUser.js
const mongoose = require('mongoose');

const deletedUserSchema = new mongoose.Schema({
    email: { type: String, lowercase: true, trim: true },
    phone: { type: String },
    fullName: { type: String },
    reason: { type: String },
    archivedAt: { type: Date, default: Date.now },
    meta: { type: Object, default: {} } // optional metadata (IP, user agent, etc)
}, { timestamps: true });

module.exports = mongoose.model('DeletedUser', deletedUserSchema);
