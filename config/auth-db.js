const Database = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
require("dotenv").config();

const db = new Database(path.join(__dirname, "../auth_server.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS authorization_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

try {
  const testUser = process.env.BATAUTH_TEST_USER;
  const testEmail = process.env.BATAUTH_TEST_EMAIL;
  const testPassword = process.env.BATAUTH_TEST_PASSWORD;

  if (testUser && testEmail && testPassword) {
    const existing = db.prepare("SELECT id FROM users WHERE username = ?").get(testUser);
    if (!existing) {
      const hash = bcrypt.hashSync(testPassword, 10);
      db.prepare(
        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)"
      ).run(testUser, testEmail, hash, new Date().toISOString());
      console.log(`[authdb] compte de test ${testUser} cree dans auth_server.db`);
    }
  }
} catch (err) {
  console.error("[authdb] erreur lors du seeding du compte de test:", err);
}

module.exports = db;

