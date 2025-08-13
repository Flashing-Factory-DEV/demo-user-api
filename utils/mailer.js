// utils/mailer.js
const nodemailer = require('nodemailer');

let transporterPromise = null;

async function getTransporter() {
  if (transporterPromise) return transporterPromise;

  transporterPromise = (async () => {
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
      return nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: Number(process.env.SMTP_PORT) === 465,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
    }

    // If you set ETHEREAL_EMAIL_USERNAME / ETHEREAL_EMAIL_PASSWORD in env, use them.
    return nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false,
      auth: {
        user: process.env.ETHEREAL_EMAIL_USERNAME,
        pass: process.env.ETHEREAL_EMAIL_PASSWORD
      }
    });
  })();

  return transporterPromise;
}

/**
 * Send a verification email containing a code or short text.
 * Returns: { previewUrl?, info, codeOrText }.
 */
async function sendVerificationEmail(email, codeOrText, ttlMinutes = 30, opts = {}) {
  const transporter = await getTransporter();

  const subject = opts.subject || 'Your verification code';
  const text = opts.text || `Your verification code is: ${codeOrText} (expires in ${ttlMinutes} seconds)`;
  const html = opts.html || `<p>Your verification code is: <strong>${codeOrText}</strong></p><p>Expires in ${ttlMinutes} seconds.</p>`;

  const mailOptions = {
    from: process.env.FROM_EMAIL || 'no-reply@flashing-factory-dev.com',
    to: email,
    subject,
    text,
    html,
  };

  const info = await transporter.sendMail(mailOptions);
  const previewUrl = nodemailer.getTestMessageUrl(info) || null;

  // Return helpful info for dev clients (include code/text for testing)
  return { previewUrl, info, codeOrText };
}

/**
 * Send an email containing a reset/change link.
 * Returns: { previewUrl?, info, link }.
 */
async function sendEmailWithLink(email, link, ttlMinutes = 60, opts = {}) {
  const transporter = await getTransporter();

  const subject = opts.subject || 'Action required: link';
  const text = opts.text || `Click this link to continue: ${link}\nThis link expires in ${ttlMinutes} minutes.`;
  const html = opts.html || `<p>Click this link to continue: <a href="${link}">${link}</a></p><p>Expires in ${ttlMinutes} minutes.</p>`;

  const mailOptions = {
    from: process.env.FROM_EMAIL || 'no-reply@example.com',
    to: email,
    subject,
    text,
    html,
  };

  const info = await transporter.sendMail(mailOptions);
  const previewUrl = nodemailer.getTestMessageUrl(info) || null;

  return { previewUrl, info, link };
}

module.exports = { sendVerificationEmail, sendEmailWithLink };
