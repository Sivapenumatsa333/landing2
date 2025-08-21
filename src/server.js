// src/server.js
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const passport = require("passport");
require("dotenv").config();

const { init } = require("./db");
const authRoutes = require("./authRoutes");
const { requireAuth } = require("./middleware.auth");
require("./socialAuth"); // <-- Load Google & Microsoft strategies

const app = express();
const PORT = process.env.PORT || 4000;
const ORIGIN = process.env.CORS_ORIGIN || "*";

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ORIGIN === "*" ? true : ORIGIN,
    credentials: true,
  })
);

// Initialize passport
app.use(passport.initialize());

// Init DB (run schema if needed)
init().catch((err) => console.error("DB init error", err));

// Health check route
app.get("/", (req, res) =>
  res.json({ status: "ok", message: "Career backend (MySQL + Social Logins) is running 🚀" })
);

// Auth routes
app.use("/api/auth", authRoutes);

// Example protected endpoint
app.get("/api/protected", requireAuth, (req, res) => {
  res.json({ message: "✅ You are authenticated", user: req.user });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server listening on http://localhost:${PORT}`);
});
