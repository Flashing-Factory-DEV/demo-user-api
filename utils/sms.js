// utils/sms.js
// For dev: logs the SMS and returns the code in response.
// Replace with Twilio/AWS SNS integration in production.

async function sendVerificationSMS(phone, code, opts = {}) {
    // In real integration you'd call your SMS provider here and return provider response.
    const message = `SMS to ${phone}: Your verification code is ${code}`;
    console.log(message);
  
    // Example shape to return: { ok: true, provider: {...}, code }
    return { ok: true, provider: { message }, code };
  }
  
  module.exports = { sendVerificationSMS };
  