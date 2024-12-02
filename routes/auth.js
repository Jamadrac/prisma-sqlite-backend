const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const router = express.Router();
const prisma = new PrismaClient();

// Configuration
const config = {
  jwt: {
    secret: "your_jwt_secret", // Replace with a strong secret key
    expiresIn: "1h",
    algorithm: "HS256",
  },
  email: {
    service: "Gmail",
    user: "your-email@gmail.com",
    password: "your-email-password",
  },
  security: {
    bcryptRounds: 10,
    otpExpiryTime: 10 * 60 * 1000, // 10 minutes in milliseconds
    passwordRegex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$/,
  },
};

// Mailer setup
const transporter = nodemailer.createTransport({
  service: config.email.service,
  auth: {
    user: config.email.user,
    pass: config.email.password,
  },
});

// Helper for OTP attempts rate-limiting
const otpAttempts = new Map();

// Helper Functions
const isStrongPassword = (password) =>
  config.security.passwordRegex.test(password);
const isRateLimited = (key, attemptsMap) => {
  const attempts = attemptsMap.get(key) || { count: 0, timestamp: Date.now() };
  if (
    attempts.count >= 3 &&
    Date.now() - attempts.timestamp < config.security.otpExpiryTime
  ) {
    return true;
  }
  return false;
};

const incrementAttempts = (key, attemptsMap) => {
  const attempts = attemptsMap.get(key) || { count: 0, timestamp: Date.now() };
  attempts.count++;
  if (attempts.count === 1) attempts.timestamp = Date.now();
  attemptsMap.set(key, attempts);
};

// Routes
router.post("/register", async (req, res) => {
  try {
    const { email, password, profileImage } = req.body;

    if (!isStrongPassword(password)) {
      throw new Error("Password does not meet security requirements");
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new Error("User already exists");
    }

    const hashedPassword = await bcrypt.hash(
      password,
      config.security.bcryptRounds
    );

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        profileImage, // Assuming you're passing a valid image string
      },
    });

    res
      .status(201)
      .json({ message: "User registered successfully", userId: user.id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error("Invalid credentials");
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn, algorithm: config.jwt.algorithm }
    );

    res.status(200).json({ token, userId: user.id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (isRateLimited(email, otpAttempts)) {
      throw new Error("Too many OTP requests. Try again later.");
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res
        .status(200)
        .json({ message: "If the user exists, OTP has been sent." });
      return;
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = new Date(Date.now() + config.security.otpExpiryTime);

    await prisma.user.update({
      where: { email },
      data: {
        otp: await bcrypt.hash(otp, config.security.bcryptRounds),
        otpExp: otpExpiry,
      },
    });

    const mailOptions = {
      from: config.email.user,
      to: email,
      subject: "Password Reset OTP",
      html: `<p>Your OTP for password reset is: <strong>${otp}</strong></p><p>This OTP will expire in 10 minutes.</p>`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: "If the user exists, OTP has been sent." });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!isStrongPassword(newPassword)) {
      throw new Error("Password does not meet security requirements");
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.otp || !user.otpExp || new Date() > user.otpExp) {
      throw new Error("Invalid or expired reset request");
    }

    const isValidOTP = await bcrypt.compare(otp, user.otp);
    if (!isValidOTP) {
      throw new Error("Invalid or expired reset request");
    }

    const hashedPassword = await bcrypt.hash(
      newPassword,
      config.security.bcryptRounds
    );

    await prisma.user.update({
      where: { email },
      data: {
        password: hashedPassword,
        otp: null,
        otpExp: null,
      },
    });

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.get("/protected", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      throw new Error("No token provided");
    }

    const decoded = jwt.verify(token, config.jwt.secret, {
      algorithms: [config.jwt.algorithm],
    });

    res
      .status(200)
      .json({ message: "This is a protected route", user: decoded });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Export the router
module.exports = router;
