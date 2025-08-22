// src/authRoutes.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const { pool } = require('./db'); // PostgreSQL pool
const passport = require("passport");
const {
  registerEmployee,
  registerEmployer,
  registerRecruiter,
  login: loginValidator
} = require('./validators');
const { requireAuth } = require('./middleware.auth');

require('dotenv').config();

const router = express.Router();
const COOKIE_NAME = process.env.COOKIE_NAME || 'token';

// ------------------- Helpers -------------------
function signToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, name: user.name, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

// ------------------- LOGIN -------------------

// Employee + Recruiter Login
router.post('/login', loginValidator, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    // ❌ Employers blocked here
    if (user.role === 'employer') {
      return res.status(403).json({ error: 'Employers must use Employer Login' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid email or password' });

    const token = signToken(user);
    setAuthCookie(res, token);

    return res.json({
      message: `${user.role} logged in`,
      user: { id: user.id, role: user.role, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Employer Login
router.post('/login/employer', loginValidator, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Invalid email or password' });

    if (user.role !== 'employer') {
      return res.status(403).json({ error: 'Only employers can login here' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid email or password' });

    const token = signToken(user);
    setAuthCookie(res, token);

    return res.json({
      message: 'Employer logged in',
      user: { id: user.id, role: user.role, name: user.name, email: user.email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ------------------- LOGOUT -------------------
router.post('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ message: 'Logged out' });
});

// ------------------- ME -------------------
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ------------------- REGISTER -------------------
router.post('/register/employee', registerEmployee, async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

  const { name, email, password, phone, work_status } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length) return res.status(400).json({ error: 'Email already exists' });

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, phone, work_status)
       VALUES ($1, $2, $3, 'employee', $4, $5)
       RETURNING id`,
      [name, email, hash, phone || null, work_status || null]
    );

    const insertId = result.rows[0].id;
    const token = signToken({ id: insertId, role: 'employee', name, email });
    setAuthCookie(res, token);
    return res.status(201).json({
      message: 'Employee registered',
      user: { id: insertId, role: 'employee', name, email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/register/employer', registerEmployer, async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

  const { name, email, password, company_name, website, gst_number } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length) return res.status(400).json({ error: 'Email already exists' });

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, company_name, website, gst_number)
       VALUES ($1, $2, $3, 'employer', $4, $5, $6)
       RETURNING id`,
      [name, email, hash, company_name || null, website || null, gst_number || null]
    );

    const insertId = result.rows[0].id;
    const token = signToken({ id: insertId, role: 'employer', name, email });
    setAuthCookie(res, token);
    return res.status(201).json({
      message: 'Employer registered',
      user: { id: insertId, role: 'employer', name, email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/register/recruiter', registerRecruiter, async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

  const { name, email, password, agency_name, specialization, years_experience } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length) return res.status(400).json({ error: 'Email already exists' });

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, agency_name, specialization, years_experience)
       VALUES ($1, $2, $3, 'recruiter', $4, $5, $6)
       RETURNING id`,
      [name, email, hash, agency_name || null, specialization || null, years_experience || 0]
    );

    const insertId = result.rows[0].id;
    const token = signToken({ id: insertId, role: 'recruiter', name, email });
    setAuthCookie(res, token);
    return res.status(201).json({
      message: 'Recruiter registered',
      user: { id: insertId, role: 'recruiter', name, email }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});




// ========================
// GOOGLE LOGIN (Postgres)
// ========================
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    try {
      // Default role = employee
      const { id, displayName, emails } = req.user;
      const email = emails[0].value;

      const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      let user;
      if (result.rows.length === 0) {
        const insert = await pool.query(
          "INSERT INTO users (name, email, role, provider_id) VALUES ($1, $2, 'employee', $3) RETURNING *",
          [displayName, email, id]
        );
        user = insert.rows[0];
      } else {
        user = result.rows[0];
      }

      const token = signToken(user);
      setAuthCookie(res, token);
      res.redirect("http://localhost:8081/page2.html"); // ✅ frontend dashboard
    } catch (err) {
      console.error(err);
      res.redirect("http://localhost:8081/page2.html?error=google_login_failed");
    }
  }
);

// ========================
// MICROSOFT LOGIN (Postgres)
// ========================
router.get(
  "/microsoft",
  passport.authenticate("azuread-openidconnect", { failureRedirect: "/" })
);

router.post(
  "/microsoft/callback",
  passport.authenticate("azuread-openidconnect", { session: false, failureRedirect: "/" }),
  async (req, res) => {
    try {
      // Default role = employee
      const email = req.user._json.preferred_username;
      const name = req.user.displayName || email;

      const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      let user;
      if (result.rows.length === 0) {
        const insert = await pool.query(
          "INSERT INTO users (name, email, role, provider_id) VALUES ($1, $2, 'employee', $3) RETURNING *",
          [name, email, req.user.oid]
        );
        user = insert.rows[0];
      } else {
        user = result.rows[0];
      }

      const token = signToken(user);
      setAuthCookie(res, token);
      res.redirect("http://localhost:8081/page2.html"); // ✅ redirect to FE
    } catch (err) {
      console.error(err);
      res.redirect("http://localhost:8081/page2.html?error=microsoft_login_failed");
    }
  }
);

module.exports = router;

