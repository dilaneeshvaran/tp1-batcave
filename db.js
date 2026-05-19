const Database = require("better-sqlite3");
const db = new Database("database.db");

db.prepare(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )
`,
).run();

module.exports = db;
