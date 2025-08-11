// middleware/ensureUserVerified.js
const User = require('../models/User')

module.exports = async function ensureUserVerified(req, res, next) {
    try {
        // Assuming req.user is populated by your auth middleware and contains user's ID
        const user = req.user;

        if (!user) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        console.log(user)

        // Check the required fields
        if (!user.verified || !user.emailVerified || !user.phoneVerified) {
            return res.status(403).json({
                error: 'User account not fully verified. Please complete all verification steps.',
            });
        }

        next();
    } catch (error) {
        console.error('Verification middleware error:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
};
