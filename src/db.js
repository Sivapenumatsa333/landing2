// src/db.js
const { Pool } = require("pg");
require("dotenv").config();

// ✅ PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render provides this
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// ✅ Initialize schema if not exists
async function init() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT,
        role VARCHAR(50) NOT NULL DEFAULT 'employee',
        phone VARCHAR(20),
        work_status VARCHAR(50),
        company_name VARCHAR(255),
        website VARCHAR(255),
        gst_number VARCHAR(100),
        agency_name VARCHAR(255),
        specialization VARCHAR(255),
        years_experience INT,
        provider_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("✅ PostgreSQL schema ready");
  } catch (err) {
    console.error("❌ DB init error", err);
  }
}

module.exports = { pool, init };
