// utils/sms.js
const { sendVerificationEmail } = require('./mailer');

async function sendVerificationSMS(phone, code, opts = {}) {
  // In dev/non-prod we'll deliver "SMS" messages to your Ethereal email so you can inspect them.
  if (process.env.NODE_ENV !== 'production' || true) {
    const devRecipient = process.env.ETHEREAL_SMS_RECIPIENT || process.env.ETHEREAL_EMAIL_USERNAME;
    const subject = opts.subject || `SMS to ${phone}`;
    const text = opts.text || `SMS to ${phone}: Your verification code is ${code}`;
    const html = opts.html || `<p>SMS to <strong>${phone}</strong>: Your verification code is <strong>${code}</strong></p>`;

    // Reuse the email sender so the message appears in Ethereal messages.
    // We pass code as codeOrText so the caller still receives the code in the return structure.
    const { previewUrl, info, codeOrText } = await sendVerificationEmail(devRecipient, code, 0, { subject, text, html });
    return { ok: true, provider: { info, previewUrl }, code };
  }

  // Production: replace this with real SMS provider integration (Twilio, SNS, etc.)
  // Example placeholder:
  // const providerResp = await twilioClient.messages.create({ to: phone, body: `Your code is ${code}` });
  // return { ok: true, provider: providerResp, code };

  // If not implemented, return an error so you don't silently skip sending SMS in prod.
  throw new Error('SMS provider not configured for production');
}

module.exports = { sendVerificationSMS };
