const Database = require("better-sqlite3");
const db = new Database("database.db");

db.exec(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  );
  
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`,
);

module.exports = db;
