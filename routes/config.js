// config.js
const config = {
  email: {
    user: "your-email@gmail.com",
    password: "your-app-specific-password",
    service: "gmail",
  },
  jwt: {
    secret: "your-secure-jwt-secret-key",
    expiresIn: "1h",
    algorithm: "HS256",
  },
  security: {
    bcryptRounds: 12,
    maxLoginAttempts: 5,
    loginLockoutTime: 15 * 60 * 1000,
    otpExpiryTime: 10 * 60 * 1000,
    passwordRegex:
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  },
  prisma: {
    logLevel: "error",
  },
};

if (process.env.NODE_ENV === "production") {
  config.email.user = process.env.EMAIL_USER;
  config.email.password = process.env.EMAIL_PASSWORD;
  config.jwt.secret = process.env.JWT_SECRET;
}

module.exports = config;
