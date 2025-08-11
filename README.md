# Flashing Factory — Auth API

This repository contains the authentication API used by the Flashing Factory demo project. It implements email verification, phone verification, password reset, change-phone/email flows, and account deletion — built with Express + Mongoose.

> This README summarizes installation, configuration, project structure and the available routes. The full developer HTML documentation (API + Models) is in the `Auth API — Developer Docs (Updated)` document.

---

## Quick start (development)

Requirements:

- Node.js (v16+ recommended)
- npm or yarn
- MongoDB running (local or remote)

Install:

```bash
# clone
git clone <repo-url>
cd <repo>

# install deps
npm install
# or
# yarn install
```

Create a `.env` file (example below) and start:

```bash
# start dev with nodemon (if installed)
npm run dev

# or start normally
npm start
```

## Example `.env`

```
PORT=3000
MONGO_URI=mongodb://localhost:27017/flashing-factory
NODE_ENV=development
APP_URL=http://localhost:3000

# JWT
JWT_SECRET=your_jwt_secret_here
JWT_EXPIRES_IN=7d

# Code TTLs (seconds or durations like '5m')
MAIN_CODE_TTL_SEC=300           # email/phone verification codes lifetime
PASSWORD_RESET_TOKEN_EXPIRES=3600
CHANGE_EMAIL_REQUEST_EXPIRES=3600
DELETE_CONFIRM_TOKEN_EXPIRES=600

# Mailer/SMS provider config (example placeholders)
MAILER_HOST=smtp.example.com
MAILER_USER=...
MAILER_PASS=...
SMS_PROVIDER=dev

```

> Note: in production you should set secure HTTPS and real providers (Twilio, AWS SNS, SendGrid, etc.).

---

## Project structure (important files)

```
├─ src/ (or root)
│  ├─ routes/auth.js      # all the auth routes mounted at /api/auth
│  ├─ models/
│  │   ├─ User.js
│  │   ├─ VerificationCode.js
│  │   ├─ PhoneVerificationCode.js
│  │   ├─ PasswordReset.js
│  │   └─ DeletedUser.js
│  ├─ utils/
│  │   ├─ mailer.js      # sendVerificationEmail, sendEmailWithLink
│  │   └─ sms.js         # sendVerificationSMS
│  ├─ middleware/
│  │   ├─ auth.js        # JWT cookie/header extractor
│  │   └─ ensureUserVerified.js
│  ├─ app.js / server.js
│  └─ .env
```

---

## Environment & deployment notes

- `auth_token` cookie: HttpOnly cookie is used by default (see cookie options in code). In dev you may still return tokens in JSON for testing, but prefer secure HttpOnly cookies in production.
- TTLs & tokens: Verification / reset records use `expiresAt` and TTL indexes. In production consider hashing tokens stored in the DB instead of storing raw tokens.
- Rate limiting: `send-code` endpoint is protected by `express-rate-limit` to avoid abuse.
- Phone/email providers: `utils/mailer.js` and `utils/sms.js` are pluggable. For local development those helpers may return a preview URL or the code directly.

---

## Routes summary (mounted at `/api/auth`)

> All routes return JSON in the shape `{ ok: true/false, ... }` and proper HTTP status codes.

### Public

- `POST /check-email` — checks whether an email exists and is verified. Body: `{ email }`.
- `POST /send-code` — send email verification code. Body: `{ email }`. Rate-limited.
- `POST /verify-code` — verify email code. Body: `{ email, code }`.
- `POST /register` — create/update user & send phone verification code. Body: `{ email, fullName, phone, password }`.
- `POST /resend-phone-code` — resend phone code. Body: `{ email, phone }`.
- `POST /verify-phone-code` — verify phone code and return a JWT cookie. Body: `{ phone, code }`.
- `POST /login` — email + password login. Body: `{ email, password }`.
- `POST /reset-password-request` — request password reset link. Body: `{ email }`.
- `POST /reset-password` — perform reset with token. Body: `{ token, newPassword }`.

### Authenticated (require JWT cookie or Authorization header)

- `GET /profile` — get current user profile.
- `POST /logout` — clear auth cookie.
- `POST /update-fullname` — update `fullName`.
- `POST /change-phone-request` — request phone change (sends code to new phone). Body: `{ newPhone }`.
- `POST /change-phone-verify` — verify phone change. Body: `{ newPhone, code }`.
- `POST /change-email-request` — begin change-email flow (sends token to old email). Body: `{ newEmail }`.
- `POST /change-email-verify-old` — verify old email token. Body: `{ requestId, code }`.
- `POST /resend-new-email-code` — resend token to new email. Body: `{ requestId }`.
- `POST /change-email-verify-new` — verify new email token and finalize change. Body: `{ requestId, code }`.
- `POST /delete-account-verify` — confirm password and receive short-lived delete token. Body: `{ password }`.
- `POST /delete-account` — confirm account deletion using token & reason. Body: `{ deleteToken, reason }`.

---

## Models (quick)

The main Mongoose models are:

- `User` — stores `email`, `passwordHash`, `fullName`, `phone`, `emailVerified`, `phoneVerified`, soft-delete flags, timestamps.
- `VerificationCode` — email verification codes with `email`, `code`, `expiresAt`, `used`.
- `PhoneVerificationCode` — phone codes with `phone`, `code`, `purpose`, `expiresAt`, `attempts`.
- `PasswordReset` — tokens for password reset (and reused for delete-account confirm) with `userId`, `token`, `purpose`, `expiresAt`, `used`.
- `DeletedUser` — archived record kept when a user deletes their account.

(Full model definitions are available in the `Auth API — Developer Docs (Updated)` document in the canvas.)

---

## Testing and development tips

- Use Postman or curl to test endpoints. Consider importing an exported Postman collection if you want a quick test suite (I can generate one from the routes).
- For dev, set `SMS_PROVIDER=dev` and `MAILER=ethereal` (or whichever helper returns a `previewUrl`) so codes/links appear in responses.
- Watch TTL behavior: MongoDB TTL indexes remove expired docs, but they run periodically — don't rely on immediate removal for logic.

---

## Next steps I can help with

- Generate an OpenAPI (Swagger) JSON for these routes.
- Produce a Postman collection export.
- Create example frontend auth flows (React/Next) that integrate with these endpoints (including HttpOnly cookie handling).

---

_README created by the assistant — let me know if you want this saved as a file in the repository or exported as a downloadable .md._
