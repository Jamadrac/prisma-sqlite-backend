// auth.js
const { PrismaClient } = require("@prisma/client");
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const prisma = new PrismaClient();

// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// User model extension for Prisma schema
/*
model User {
  id            Int      @id @default(autoincrement())
  email         String   @unique
  password      String
  profileImage  String?  // Base64 string
  resetToken    String?
  resetTokenExp DateTime?
  otp          String?
  otpExp       DateTime?
  createdAt    DateTime @default(now())
}
*/

class AuthService {
  // Register new user
  async register(email, password, profileImage) {
    try {
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        throw new Error("User already exists");
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          profileImage: profileImage, // Base64 string
        },
      });

      return { message: "User registered successfully", userId: user.id };
    } catch (error) {
      throw error;
    }
  }

  // Login user
  async login(email, password) {
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
        throw new Error("User not found");
      }

      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        throw new Error("Invalid password");
      }

      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      return { token, userId: user.id };
    } catch (error) {
      throw error;
    }
  }

  // Generate and send OTP for password reset
  async forgotPassword(email) {
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
        throw new Error("User not found");
      }

      // Generate 6-digit OTP
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes validity

      // Save OTP and expiry in database
      await prisma.user.update({
        where: { email },
        data: {
          otp,
          otpExp: otpExpiry,
        },
      });

      // Send email with OTP
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset OTP",
        html: `
          <h1>Password Reset Request</h1>
          <p>Your OTP for password reset is: <strong>${otp}</strong></p>
          <p>This OTP will expire in 15 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      };

      await transporter.sendMail(mailOptions);
      return { message: "OTP sent successfully" };
    } catch (error) {
      throw error;
    }
  }

  // Verify OTP and update password
  async resetPassword(email, otp, newPassword) {
    try {
      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) {
        throw new Error("User not found");
      }

      if (!user.otp || !user.otpExp) {
        throw new Error("No OTP request found");
      }

      if (user.otp !== otp) {
        throw new Error("Invalid OTP");
      }

      if (new Date() > user.otpExp) {
        throw new Error("OTP has expired");
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Update password and clear OTP fields
      await prisma.user.update({
        where: { email },
        data: {
          password: hashedPassword,
          otp: null,
          otpExp: null,
        },
      });

      return { message: "Password updated successfully" };
    } catch (error) {
      throw error;
    }
  }

  // Update profile image
  async updateProfileImage(userId, imageBase64) {
    try {
      await prisma.user.update({
        where: { id: userId },
        data: {
          profileImage: imageBase64,
        },
      });

      return { message: "Profile image updated successfully" };
    } catch (error) {
      throw error;
    }
  }

  // Middleware to verify JWT token
  verifyToken(req, res, next) {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) {
        throw new Error("No token provided");
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ error: "Invalid token" });
    }
  }
}

module.exports = new AuthService();
