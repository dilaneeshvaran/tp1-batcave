const Database = require("better-sqlite3");
const path = require("path");
const db = new Database(path.join(__dirname, "../database.db"));

db.exec(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'USER',
    two_factor_secret TEXT,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    provider TEXT NOT NULL DEFAULT 'local',
    provider_user_id TEXT,
    email TEXT
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    timestamp TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS connexions_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`,
);

try {
  db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'USER'");
} catch (_) {}

try {
  db.exec("ALTER TABLE users ADD COLUMN two_factor_secret TEXT");
} catch (_) {}

try {
  db.exec("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0");
} catch (_) {}

try {
  db.exec("ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'local'");
} catch (_) {}

try {
  db.exec("ALTER TABLE users ADD COLUMN provider_user_id TEXT");
} catch (_) {}

try {
  db.exec("ALTER TABLE users ADD COLUMN email TEXT");
} catch (_) {}

try {
  db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_provider_id ON users(provider, provider_user_id)");
} catch (_) {}

try {
  db.exec("ALTER TABLE refresh_tokens RENAME COLUMN used TO is_used");
} catch (_) {}

try {
  db.exec("ALTER TABLE refresh_tokens ADD COLUMN is_used INTEGER NOT NULL DEFAULT 0");
} catch (_) {}

module.exports = db;
