const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const nodemailer = require("nodemailer");
const fs = require("fs-extra");
const dotenv = require("dotenv");

dotenv.config();
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static("frontend"));

const USERS_FILE = "./users.json";

// create file if not exist
if (!fs.existsSync(USERS_FILE)) fs.writeJSONSync(USERS_FILE, {});

// create transporter for email sending
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// === ROUTES ===

// send otp
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const otp = generateOTP();

    const users = await fs.readJSON(USERS_FILE);
    users[email] = { otp, verified: false };
    await fs.writeJSON(USERS_FILE, users);

    await transporter.sendMail({
      from: `"Email OTP Login" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}`,
    });

    res.json({ success: true, message: "OTP sent to your email!" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Error sending OTP." });
  }
});

// verify otp
app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const users = await fs.readJSON(USERS_FILE);

    if (users[email] && users[email].otp === otp) {
      users[email].verified = true;
      await fs.writeJSON(USERS_FILE, users);
      res.json({ success: true, message: "Login successful!" });
    } else {
      res.json({ success: false, message: "Invalid OTP!" });
    }
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Server error." });
  }
});

app.listen(process.env.PORT || 3000, () =>
  console.log(`✅ Server running on port ${process.env.PORT || 3000}`)
);
