const jwt = require('jsonwebtoken');
const User = require('../models/User')


async function authMiddleware(req, res, next) {
  // Look for the token in cookies
  const token = req.cookies?.auth_token;

  console.log(token)

  if (!token) {
    return res.status(401).json({ error: 'missing token' });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev_jwt_secret');
    req.user = payload;

    const user = await User.findOne({ email: req.user.email })

    console.log(user, user.verified, user.emailVerified, user.phoneVerified)

    if (!user.verified || !user.emailVerified || !user.phoneVerified) {
      return res.status(403).json({
        error: 'User account not fully verified. Please complete all verification steps.',
      });
    }

    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

module.exports = authMiddleware;
