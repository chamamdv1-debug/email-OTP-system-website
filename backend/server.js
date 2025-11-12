require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const fs = require('fs-extra');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const OTP_EXPIRES_SECONDS = parseInt(process.env.OTP_EXPIRES_SECONDS || '300', 10);
const TOKEN_EXPIRES_SECONDS = parseInt(process.env.TOKEN_EXPIRES_SECONDS || '900', 10);

const USERS_FILE = path.join(__dirname, 'users.json');

// in-memory stores (for demo). Production: Redis/DB.
const otpStore = new Map(); // email -> { otp, expiresAt, attempts }
const tokenStore = new Map(); // token -> { email, expiresAt }

async function readUsers() {
  try {
    const exists = await fs.pathExists(USERS_FILE);
    if (!exists) {
      await fs.writeJson(USERS_FILE, []);
      return [];
    }
    return await fs.readJson(USERS_FILE);
  } catch (err) {
    console.error('readUsers error', err);
    return [];
  }
}

async function writeUsers(users) {
  try {
    await fs.writeJson(USERS_FILE, users, { spaces: 2 });
    return true;
  } catch (err) {
    console.error('writeUsers error', err);
    return false;
  }
}

function generateOTP(len = 6) {
  let otp = '';
  for (let i = 0; i < len; i++) otp += Math.floor(Math.random() * 10);
  return otp;
}

function generateToken() {
  return crypto.randomBytes(20).toString('hex');
}

// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: parseInt(process.env.SMTP_PORT || '587', 10) === 465, // true for 465
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Simple cleanup interval for expired OTPs/tokens
setInterval(() => {
  const now = Date.now();
  for (const [email, obj] of otpStore.entries()) {
    if (obj.expiresAt <= now) otpStore.delete(email);
  }
  for (const [token, obj] of tokenStore.entries()) {
    if (obj.expiresAt <= now) tokenStore.delete(token);
  }
}, 60 * 1000);

// Endpoint: send OTP
app.post('/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ ok: false, error: 'Email required' });

  const existing = otpStore.get(email);
  if (existing && existing.expiresAt > Date.now()) {
    // Prevent super frequent resends
    const secsLeft = Math.ceil((existing.expiresAt - Date.now()) / 1000);
    if (secsLeft > OTP_EXPIRES_SECONDS - 250) {
      return res.status(429).json({ ok: false, error: 'Try again later' });
    }
  }

  const otp = generateOTP(6);
  const expiresAt = Date.now() + OTP_EXPIRES_SECONDS * 1000;
  otpStore.set(email, { otp, expiresAt, attempts: 0 });

  const mailOptions = {
    from: `"${process.env.FROM_NAME || 'No Reply'}" <${process.env.FROM_EMAIL || process.env.SMTP_USER}>`,
    to: email,
    subject: 'Your verification code',
    text: `Your verification code is: ${otp}. It expires in ${Math.ceil(OTP_EXPIRES_SECONDS/60)} minutes.`,
    html: `<div style="font-family:Arial,Helvetica,sans-serif">
            <h3>Verify your identity</h3>
            <p>Your verification code is:</p>
            <div style="font-size:22px;font-weight:700;letter-spacing:4px;background:#111;padding:8px;border-radius:6px;display:inline-block;color:#fff">${otp}</div>
            <p style="color:#666">It expires in ${Math.ceil(OTP_EXPIRES_SECONDS/60)} minutes.</p>
           </div>`
  };

  try {
    await transporter.sendMail(mailOptions);
    return res.json({ ok: true, message: 'OTP sent' });
  } catch (err) {
    console.error('sendMail error', err);
    return res.status(500).json({ ok: false, error: 'Failed to send email' });
  }
});

// Endpoint: verify OTP (returns token if ok)
app.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ ok: false, error: 'Email and OTP required' });

  const data = otpStore.get(email);
  if (!data) return res.status(400).json({ ok: false, error: 'No OTP requested or already used' });

  if (Date.now() > data.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ ok: false, error: 'OTP expired' });
  }

  data.attempts = (data.attempts || 0) + 1;
  if (data.attempts > 6) {
    otpStore.delete(email);
    return res.status(429).json({ ok: false, error: 'Too many attempts' });
  }

  if (otp !== data.otp) {
    return res.status(400).json({ ok: false, error: 'Invalid OTP' });
  }

  // success: generate token, store mapping, remove otp
  const token = generateToken();
  tokenStore.set(token, { email, expiresAt: Date.now() + TOKEN_EXPIRES_SECONDS * 1000 });
  otpStore.delete(email);

  return res.json({ ok: true, message: 'Verified', token });
});

// Endpoint: register user (requires token)
app.post('/register', async (req, res) => {
  const { name, email, token } = req.body;
  if (!name || !email || !token) return res.status(400).json({ ok: false, error: 'Name, email and token required' });

  const mapping = tokenStore.get(token);
  if (!mapping || mapping.email !== email) return res.status(400).json({ ok: false, error: 'Invalid or expired token' });

  // load users
  const users = await readUsers();
  const exists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (exists) return res.status(400).json({ ok: false, error: 'User already exists' });

  const user = { id: crypto.randomBytes(8).toString('hex'), name, email, createdAt: Date.now() };
  users.push(user);
  const ok = await writeUsers(users);
  if (!ok) return res.status(500).json({ ok: false, error: 'Failed to save user' });

  // optionally delete token after use
  tokenStore.delete(token);

  return res.json({ ok: true, message: 'Registered', user });
});

// Endpoint: login (if want to check user exists before send otp) - optional
app.post('/exists', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ ok: false, error: 'Email required' });
  const users = await readUsers();
  const exists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  return res.json({ ok: true, exists: !!exists });
});

// Endpoint: get current user by token (for frontend dashboard)
app.get('/me', async (req, res) => {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return res.status(401).json({ ok: false, error: 'Token required' });
  const mapping = tokenStore.get(token);
  if (!mapping) return res.status(401).json({ ok: false, error: 'Invalid or expired token' });

  const users = await readUsers();
  const user = users.find(u => u.email.toLowerCase() === mapping.email.toLowerCase());
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

  return res.json({ ok: true, user });
});

app.listen(PORT, () => {
  console.log(`OTP server running on port ${PORT}`);
});
