// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String },
  fullName: { type: String },
  phone: { type: String, index: true, unique: true, },
  // overall account status (you can use separate flags below)
  verified: { type: Boolean, default: false }, // deprecated/optional - kept for backward compat
  emailVerified: { type: Boolean, default: false },
  phoneVerified: { type: Boolean, default: false },

  // soft-delete / administrative fields
  deleted: { type: Boolean, default: false },
  deletedAt: { type: Date, default: null },

  // timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date }
}, {
  timestamps: true
});

// Update 'updatedAt' automatically (mongoose timestamps do this; this line optional)
userSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('User', userSchema);
