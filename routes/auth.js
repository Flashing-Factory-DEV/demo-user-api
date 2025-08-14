const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../models/User');
const VerificationCode = require('../models/VerificationCode');
const { sendVerificationEmail, sendEmailWithLink } = require('../utils/mailer');
const authMiddleware = require('../middleware/auth');
const ensureUserVerified = require('../middleware/ensureUserVerified');

// === Helpers & extra model requires ===
const crypto = require('crypto');
const PasswordReset = require('../models/PasswordReset');
const ChangeEmailRequest = require('../models/ChangeEmailRequest');
const DeletedUser = require('../models/DeletedUser');

const sendCodeLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, message: { error: 'Too many requests' } });

const PhoneVerificationCode = require('../models/PhoneVerificationCode');
const { sendVerificationSMS } = require('../utils/sms');

// when sending cookie from auth API
const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',        // true only on HTTPS prod
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path: '/',                // important so cookie is available across routes
    maxAge: 7 * 24 * 60 * 60 * 1000
    // domain: undefined in dev; only set domain in prod if you control shared domain
};

// Parse helper
const parseDurationToSeconds = (str) => {
    const match = /^(\d+)([smhd]?)$/.exec(str);
    if (!match) throw new Error(`Invalid duration: ${str}`);
    const value = Number(match[1]);
    const unit = match[2] || 's';
    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 3600;
        case 'd': return value * 86400;
    }
};

// Main TTL (in seconds) for all codes — change here for global effect
const MAIN_CODE_TTL_SEC = process.env.MAIN_CODE_TTL_SEC

// Email/general verification code
const VERIF_EXPIRES_SEC = MAIN_CODE_TTL_SEC

// Phone verification code
const PHONE_VERIF_EXPIRES_SEC = MAIN_CODE_TTL_SEC;

// Utility to generate random token
function randToken(len = 48) {
    return crypto.randomBytes(len).toString('hex');
}

// helper: 5-digit generator
function generate5DigitCode() {
    return Math.floor(10000 + Math.random() * 90000).toString(); // 10000-99999
}


router.post('/auth/check-email', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: 'email required' });
    const user = await User.findOne({ email: email.toLowerCase(), verified: true });
    res.json({ ok: true, exists: !!user });
});

router.post('/auth/send-code', sendCodeLimiter, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ ok: false, error: 'email required', apiCode: '100101' });

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        console.log(email, existingUser)
        if (existingUser) return res.status(400).json({ ok: false, error: 'email already registered', apiCode: '100102' });

        // check for an unexpired code
        const now = new Date();
        const active = await VerificationCode.findOne({
            email: email.toLowerCase(),
            used: false,
            expiresAt: { $gt: now }
        }).sort({ createdAt: -1 });

        if (active) {
            const waitMs = active.expiresAt - now;
            return res.status(429).json({ ok: false, error: `Please wait ${Math.ceil(waitMs / 1000)}s before requesting another code`, apiCode: '100103' });
        }

        const code = Math.floor(10000 + Math.random() * 90000).toString(); // 5-digit
        const expiresAt = new Date(Date.now() + VERIF_EXPIRES_SEC * 1000);
        await VerificationCode.create({ email: email.toLowerCase(), code, expiresAt });

        try {
            const { previewUrl, info, codeOrText } = await sendVerificationEmail(email, code, Math.ceil(VERIF_EXPIRES_SEC));

            const resp = { ok: true };
            if (previewUrl) resp.previewUrl = previewUrl;
            // In dev we include the code for easier testing — remove this in prod
            return res.json({ ok: true, previewUrl, code: codeOrText, apiCode: '100100' });
        } catch (err) {
            console.error(err);
            return res.status(500).json({ ok: false, error: 'failed to send email', apiCode: '100104' });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100199' });
    }
});

router.post('/auth/verify-code', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ ok: false, error: 'email and code required', apiCode: '100201' });

        const record = await VerificationCode.findOne({ email: email.toLowerCase(), code, used: false }).sort({ createdAt: -1 });
        if (!record) return res.status(400).json({ ok: false, error: 'invalid code', apiCode: '100202' });
        if (record.expiresAt < new Date()) return res.status(400).json({ ok: false, error: 'code expired', apiCode: '100203' });

        record.used = true;
        await record.save();

        let user = await User.findOne({ email: email.toLowerCase(), phone: '' });
        if (!user) user = await User.create({ email: email.toLowerCase(), emailVerified: true });

        return res.json({ ok: true, apiCode: '100200' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100299' });
    }
});

router.post('/auth/register', async (req, res) => {
    const { email, fullName, phone, password } = req.body;
    if (!email || !password || !fullName || !phone) {
        return res.status(400).json({ ok: false, error: 'email, fullName, phone, and password required', apiCode: '100301' });
    }

    const usedCode = await VerificationCode.findOne({ email: email.toLowerCase(), used: true }).sort({ createdAt: -1 });
    if (!usedCode) return res.status(400).json({ ok: false, error: 'email not verified', apiCode: '100302' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing && existing.passwordHash && existing.phoneVerified) {
        return res.status(400).json({ ok: false, error: 'email already registered', apiCode: '100303' })
    }

    const passwordHash = await bcrypt.hash(password, 12);

    // Upsert user but mark as not verified yet
    const user = await User.findOneAndUpdate(
        { email: email.toLowerCase() },
        { email: email.toLowerCase(), fullName: fullName, phone: phone, passwordHash: passwordHash, verified: false, phoneVerified: false },
        { upsert: true, new: true }
    );

    try {
        const now = new Date();

        const activePhone = await PhoneVerificationCode.findOne({
            phone,
            used: false,
            expiresAt: { $gt: now },
        }).sort({ createdAt: -1 });

        if (activePhone) {
            const waitMs = activePhone.expiresAt - now;
            return res.status(429).json({
                ok: false,
                error: `Please wait ${Math.ceil(waitMs / 1000)} seconds before requesting another phone code`, apiCode: '100304'
            });
        }

        // 5-digit phone code
        const code = Math.floor(10000 + Math.random() * 90000).toString();
        const expiresAt = new Date(Date.now() + PHONE_VERIF_EXPIRES_SEC * 1000);

        await PhoneVerificationCode.create({
            phone,
            code,
            expiresAt,
            userId: user._id,
            purpose: 'register_phone',
        });

        // Send SMS (dev helper returns code in response)
        const smsResult = await sendVerificationSMS(phone, code);

        return res.json({ ok: true, message: 'Phone verification code sent', phoneCode: smsResult.code, apiCode: '100300' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100399' });
    }
});

router.post('/auth/resend-phone-code', async (req, res) => {
    const { email, phone } = req.body;
    try {
        const now = new Date();

        // Check if there is an active (unexpired, unused) phone verification code for this phone
        const activePhone = await PhoneVerificationCode.findOne({
            phone: phone,
            used: false,
            expiresAt: { $gt: now },
        }).sort({ createdAt: -1 });

        const user = await User.findOne({
            phone: phone,
            email: email
        });

        if (activePhone) {
            const waitMs = activePhone.expiresAt - now;
            return res.status(429).json({
                ok: false,
                error: `Please wait ${Math.ceil(waitMs / 1000)} seconds before requesting another phone code`, apiCode: '100401'
            });
        }

        // Generate new 5-digit phone verification code
        const code = Math.floor(10000 + Math.random() * 90000).toString();
        const expiresAt = new Date(Date.now() + PHONE_VERIF_EXPIRES_SEC * 1000);

        await PhoneVerificationCode.create({
            phone,
            code,
            expiresAt,
            userId: user?._id, // user may be null, but that's how your current code was structured
            purpose: 'register_phone',
        });

        const smsResult = await sendVerificationSMS(phone, code);

        return res.json({ ok: true, message: 'Phone verification code sent', phoneCode: smsResult.code, apiCode: '100400' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100499' });
    }
});


// Verify phone number
router.post('/auth/verify-phone-code', async (req, res) => {
    const { phone, code } = req.body;
    console.log(phone, code)
    if (!phone || !code) return res.status(400).json({ ok: false, error: 'phone and code required', apiCode: '100501' });

    const record = await PhoneVerificationCode.findOne({ phone, code, used: false }).sort({ createdAt: -1 });
    console.log(record)
    if (!record) return res.status(400).json({ ok: false, error: 'invalid code', apiCode: '100502' });
    if (record.expiresAt < new Date()) return res.status(400).json({ ok: false, error: 'code expired', apiCode: '100503' });

    record.used = true;
    await record.save();

    try {
        const user = await User.findOneAndUpdate(
            { phone },
            { phoneVerified: true, verified: true },
            { new: true },
        );

        console.log(user)

        if (!user) return res.status(404).json({ ok: false, error: 'user not found', apiCode: '100504' });

        const token = jwt.sign(
            { sub: user._id, email: user.email },
            process.env.JWT_SECRET || 'dev_jwt_secret',
            { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
        );

        res.cookie('auth_token', token, cookieOptions);
        return res.json({ ok: true, message: 'Phone verified and logged in', user: { id: user._id, email: user.email, fullName: user.fullName, phone: user.phone }, apiCode: '100500' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100599' });
    }
});

router.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(email, password)
        if (!email || !password) return res.status(400).json({ ok: false, error: 'email and password required', apiCode: '100601' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || !user.passwordHash) return res.status(400).json({ ok: false, error: 'invalid credentials', apiCode: '100602' });

        const okPass = await bcrypt.compare(password, user.passwordHash);
        if (!okPass) return res.status(400).json({ ok: false, error: 'invalid credentials', apiCode: '100603' });

        const token = jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev_jwt_secret', { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });

        res.cookie('auth_token', token, cookieOptions);

        return res.json({ ok: true, message: 'Logged in successfully', user: { id: user._id, email: user.email, fullName: user.fullName, phone: user.phone }, apiCode: '100600' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100699' });
    }
});

// Authenticated user profile
router.get('/auth/profile', authMiddleware, async (req, res) => {
    const user = await User.findById(req.user.sub).select('-passwordHash');

    console.log('user is:', user)
    if (!user) return res.status(404).json({ ok: false, error: 'not found', apiCode: '100701' });
    res.json({ ok: true, user, apiCode: '100700' });
});

router.post('/auth/logout', async (req, res) => {
    try {
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });
        return res.json({ ok: true, message: 'Logged out', apiCode: '100800' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error', apiCode: '100699' });
    }
});

router.post('/auth/reset-password-request', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ ok: false, error: 'email required' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        // Clear any existing session cookie (logout)
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        const token = randToken(24);
        const expiresAt = new Date(Date.now() + parseDurationToSeconds(process.env.PASSWORD_RESET_TOKEN_EXPIRES || '3600') * 1000);

        await PasswordReset.create({ userId: user._id, token, expiresAt });

        // create reset link (example)
        const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password?token=${token}`;

        // send email with link
        const { previewUrl, info, link } = await sendEmailWithLink(user.email, resetLink, Math.ceil((expiresAt - Date.now()) / 60000));
        return res.json({ ok: true, message: 'Password reset link sent', previewUrl, link });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});

router.post('/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) return res.status(400).json({ ok: false, error: 'token and newPassword required' });

        const record = await PasswordReset.findOne({ token, used: false, expiresAt: { $gt: new Date() } });
        if (!record) return res.status(400).json({ ok: false, error: 'invalid or expired token' });

        const user = await User.findById(record.userId);
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        const passwordHash = await bcrypt.hash(newPassword, 12);
        user.passwordHash = passwordHash;
        await user.save();

        // mark token used
        record.used = true;
        await record.save();

        // clear cookie
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        return res.json({ ok: true, message: 'Password updated' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


router.post('/auth/update-fullname', authMiddleware, async (req, res) => {
    try {
        const { fullName } = req.body;
        if (!fullName) return res.status(400).json({ ok: false, error: 'fullName required' });

        const user = await User.findByIdAndUpdate(req.user.sub, { fullName }, { new: true }).select('-passwordHash');
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        return res.json({ ok: true, user });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


router.post('/auth/change-phone-request', authMiddleware, async (req, res) => {
    try {
        const { newPhone } = req.body;
        if (!newPhone) return res.status(400).json({ ok: false, error: 'newPhone required' });

        // check if phone is already used by another user
        const someone = await User.findOne({ phone: newPhone });
        if (someone && String(someone._id) !== String(req.user.sub)) {
            return res.status(400).json({ ok: false, error: 'phone already in use' });
        }

        const now = new Date();
        const active = await PhoneVerificationCode.findOne({
            phone: newPhone,
            used: false,
            expiresAt: { $gt: now }
        }).sort({ createdAt: -1 });

        if (active) {
            const waitMs = active.expiresAt - now;
            return res.status(429).json({ ok: false, error: `Please wait ${Math.ceil(waitMs / 1000)}s before requesting another code` });
        }

        const genCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + PHONE_VERIF_EXPIRES_SEC * 1000);
        await PhoneVerificationCode.create({ phone: newPhone, code: genCode, expiresAt, userId: req.user.sub, purpose: 'change_phone' });

        const { provider, code } = await sendVerificationSMS(newPhone, genCode);
        return res.json({ ok: true, message: provider, code: code });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


router.post('/auth/change-phone-verify', authMiddleware, async (req, res) => {
    try {
        const { newPhone, code } = req.body;
        if (!newPhone || !code) return res.status(400).json({ ok: false, error: 'newPhone and code required' });

        const record = await PhoneVerificationCode.findOne({
            phone: newPhone,
            code,
            used: false,
            purpose: 'change_phone',
            userId: req.user.sub,
            expiresAt: { $gt: new Date() }
        }).sort({ createdAt: -1 });

        if (!record) return res.status(400).json({ ok: false, error: 'invalid or expired code' });

        record.used = true;
        await record.save();

        const user = await User.findByIdAndUpdate(req.user.sub, { phone: newPhone, phoneVerified: true }, { new: true }).select('-passwordHash');
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        return res.json({ ok: true, message: 'Phone updated', user });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


// POST /auth/change-email-request
router.post('/auth/change-email-request', authMiddleware, async (req, res) => {
    try {
        const { newEmail } = req.body;
        if (!newEmail) return res.status(400).json({ ok: false, error: 'newEmail required' });

        const existing = await User.findOne({ email: newEmail.toLowerCase() });
        if (existing) return res.status(400).json({ ok: false, error: 'new email already in use' });

        const tokenOld = randToken(16);
        const tokenNew = randToken(16);
        const expiresAt = new Date(Date.now() + parseDurationToSeconds(process.env.CHANGE_EMAIL_REQUEST_EXPIRES || '3600') * 1000);

        const reqDoc = await ChangeEmailRequest.create({
            userId: req.user.sub,
            newEmail: newEmail.toLowerCase(),
            tokenOld,
            tokenNew,
            stage: 'await_old',
            expiresAt
        });

        // send code to current (old) email
        await sendVerificationEmail(
            req.user.email || (await User.findById(req.user.sub)).email,
            tokenOld,
            Math.ceil((expiresAt - Date.now()) / 60000)
        );

        // Return both for now (testing/dev only)
        return res.json({
            ok: true,
            requestId: reqDoc._id,
            code: tokenOld,
            message: 'Verification sent to your current email'
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


// POST /auth/change-email-verify-old
router.post('/auth/change-email-verify-old', authMiddleware, async (req, res) => {
    try {
        const { requestId, code } = req.body;
        if (!requestId || !code) return res.status(400).json({ ok: false, error: 'requestId and code required' });

        const reqDoc = await ChangeEmailRequest.findById(requestId);
        if (!reqDoc || reqDoc.expiresAt < new Date() || reqDoc.userId.toString() !== req.user.sub) {
            return res.status(400).json({ ok: false, error: 'invalid or expired request' });
        }
        if (reqDoc.stage !== 'await_old') return res.status(400).json({ ok: false, error: 'invalid stage' });
        if (reqDoc.tokenOld !== code) return res.status(400).json({ ok: false, error: 'invalid code' });

        reqDoc.stage = 'await_new';
        await reqDoc.save();

        await sendVerificationEmail(reqDoc.newEmail, reqDoc.tokenNew, Math.ceil((reqDoc.expiresAt - Date.now()) / 60000));

        // Return requestId + new code for now (testing/dev only)
        return res.json({
            ok: true,
            requestId: reqDoc._id,
            code: reqDoc.tokenNew,
            message: 'Old email verified. Code sent to new email'
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


// POST /auth/resend-new-email-code
router.post('/auth/resend-new-email-code', authMiddleware, async (req, res) => {
    try {
        const { requestId } = req.body;
        if (!requestId) return res.status(400).json({ ok: false, error: 'requestId required' });

        const reqDoc = await ChangeEmailRequest.findById(requestId);
        if (!reqDoc || reqDoc.expiresAt < new Date() || reqDoc.userId.toString() !== req.user.sub) {
            return res.status(400).json({ ok: false, error: 'invalid or expired request' });
        }
        if (reqDoc.stage !== 'await_new') return res.status(400).json({ ok: false, error: 'invalid stage for resending' });

        await sendVerificationEmail(reqDoc.newEmail, reqDoc.tokenNew, Math.ceil((reqDoc.expiresAt - Date.now()) / 60000));

        return res.json({
            ok: true,
            requestId: reqDoc._id,
            code: reqDoc.tokenNew, // dev only
            message: 'New email verification code resent'
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


router.post('/auth/change-email-verify-new', authMiddleware, async (req, res) => {
    try {
        const { requestId, code } = req.body;
        if (!requestId || !code) return res.status(400).json({ ok: false, error: 'requestId and code required' });

        const reqDoc = await ChangeEmailRequest.findById(requestId);
        if (!reqDoc || reqDoc.expiresAt < new Date() || reqDoc.userId.toString() !== req.user.sub) {
            return res.status(400).json({ ok: false, error: 'invalid or expired request' });
        }
        if (reqDoc.stage !== 'await_new') return res.status(400).json({ ok: false, error: 'invalid stage' });
        if (reqDoc.tokenNew !== code) return res.status(400).json({ ok: false, error: 'invalid code' });

        // Update user email
        const user = await User.findById(reqDoc.userId);
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        user.email = reqDoc.newEmail;
        user.emailVerified = true;
        await user.save();

        // cleanup
        await ChangeEmailRequest.findByIdAndDelete(requestId);

        // clear cookie to force re-auth if desired
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        return res.json({ ok: true, message: 'Email changed', user: { id: user._id, email: user.email } });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


router.post('/auth/delete-account-verify', authMiddleware, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ ok: false, error: 'password required' });

        const user = await User.findById(req.user.sub);
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        const ok = await bcrypt.compare(password, user.passwordHash || '');
        if (!ok) return res.status(400).json({ ok: false, error: 'invalid password' });

        // create a short-lived token (not JWT) — store as PasswordReset-like doc or reuse PasswordReset model
        const token = randToken(16);
        const expiresAt = new Date(Date.now() + parseDurationToSeconds(process.env.DELETE_CONFIRM_TOKEN_EXPIRES || '600') * 1000);
        // reuse PasswordReset collection for simplicity:
        await PasswordReset.create({ userId: user._id, token, expiresAt, purpose: 'delete_account' });

        return res.json({ ok: true, deleteToken: token, message: 'Use this token to confirm deletion (short-lived)' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


router.post('/auth/delete-account', authMiddleware, async (req, res) => {
    try {
        const { deleteToken, reason } = req.body;
        if (!deleteToken || !reason) return res.status(400).json({ ok: false, error: 'deleteToken and reason required' });

        const record = await PasswordReset.findOne({ token: deleteToken, used: false, purpose: 'delete_account', expiresAt: { $gt: new Date() } });
        if (!record) return res.status(400).json({ ok: false, error: 'invalid or expired token' });

        if (String(record.userId) !== String(req.user.sub)) return res.status(403).json({ ok: false, error: 'forbidden' });

        const user = await User.findById(req.user.sub);
        if (!user) return res.status(404).json({ ok: false, error: 'user not found' });

        // Archive
        await DeletedUser.create({
            email: user.email,
            phone: user.phone,
            fullName: user.fullName,
            reason,
            deletedAt: new Date()
        });

        // mark token used
        record.used = true; await record.save();

        // remove user record (or mark as deleted depending on your policy)
        await User.findByIdAndDelete(user._id);

        // clear cookie
        res.clearCookie('auth_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        return res.json({ ok: true, message: 'Account archived and removed' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ ok: false, error: 'server error' });
    }
});


module.exports = router;