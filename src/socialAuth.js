// src/socialAuth.js
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const MicrosoftStrategy = require("passport-microsoft").Strategy;
const { pool } = require("./db");

// Save user in DB if not exists
async function findOrCreateUser(profile, defaultRole = "employee") {
  const email = profile.emails?.[0]?.value;
  const name = profile.displayName || profile.name?.givenName || "Unknown";

  if (!email) throw new Error("No email from provider");

  // Check if user already exists
  const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [email]);
  if (rows.length > 0) return rows[0];

  // Insert new user (no password for social logins)
  const [result] = await pool.execute(
    `INSERT INTO users (name, email, role, password_hash)
     VALUES (?, ?, ?, '')`,
    [name, email, defaultRole]
  );

  return { id: result.insertId, name, email, role: defaultRole };
}

// Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:4000/api/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await findOrCreateUser(profile, "employee");
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

// Microsoft OAuth
passport.use(new MicrosoftStrategy({
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    callbackURL: "http://localhost:4000/api/auth/microsoft/callback",
    scope: ["user.read", "email", "openid", "profile"]
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await findOrCreateUser(profile, "employee");
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
));

// Serialize / Deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

module.exports = passport;
