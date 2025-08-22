// src/db.js
const { Pool } = require("pg");

const isRender = process.env.RENDER === "true";

// Use DATABASE_URL if provided (Render gives this automatically)
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false, // required for Render’s SSL
  },
});

async function init() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password_hash TEXT,
        role VARCHAR(50) NOT NULL,
        phone VARCHAR(20),
        work_status VARCHAR(50),
        company_name VARCHAR(150),
        website VARCHAR(200),
        gst_number VARCHAR(50),
        agency_name VARCHAR(150),
        specialization VARCHAR(150),
        years_experience INT,
        provider_id VARCHAR(200)
      );
    `);
    console.log("✅ PostgreSQL schema ready");
  } catch (err) {
    console.error("❌ DB init error", err);
  }
}

module.exports = { pool, init };
