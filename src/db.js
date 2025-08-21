// src/db.js
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const {
  DB_HOST = 'localhost',
  DB_PORT = 3306,
  DB_USER,
  DB_PASSWORD,
  DB_NAME = 'career_portal'
} = process.env;

const pool = mysql.createPool({
  host: DB_HOST,
  port: DB_PORT,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // allow executing multiple statements from schema
  multipleStatements: true
});

async function init() {
  try {
    // If DB doesn't exist, try to run the schema which includes CREATE DATABASE
    const schemaPath = path.join(__dirname, 'schema.sql');
    if (fs.existsSync(schemaPath)) {
      const schema = fs.readFileSync(schemaPath, 'utf8');
      // Use a temporary connection to run the top-level CREATE DATABASE statement (if DB doesn't exist and user has permission)
      const tmpConn = await mysql.createConnection({
        host: DB_HOST,
        port: DB_PORT,
        user: DB_USER,
        password: DB_PASSWORD,
        multipleStatements: true
      });
      await tmpConn.query(schema);
      await tmpConn.end();
    }
    console.log('MySQL schema executed or verified.');
  } catch (err) {
    console.error('Error executing schema (you may need to create DB/user manually):', err.message);
  }
}

module.exports = { pool, init };
