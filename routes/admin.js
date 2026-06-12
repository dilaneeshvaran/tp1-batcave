const express = require("express");
const path = require("path");
const db = require("../config/db");
const checkAuth = require("../middlewares/checkAuth");
const checkAdmin = require("../middlewares/checkAdmin");

const router = express.Router();

function insertLog(user) {
  db.prepare(
    "INSERT INTO logs (username, role, timestamp) VALUES (?, ?, ?)",
  ).run(user.username, user.role, new Date().toISOString());
}

router.get("/admin", checkAuth, checkAdmin, (req, res) => {
  insertLog(req.user);
  res.sendFile(path.join(__dirname, "../views/admin.html"));
});

router.get("/api/admin/users", checkAuth, checkAdmin, (req, res) => {
  const users = db.prepare("SELECT id, username, role FROM users").all();
  res.json(users);
});

router.put("/api/admin/users/:id/role", checkAuth, checkAdmin, (req, res) => {
  const { role } = req.body;
  if (!role || !["ADMIN", "USER"].includes(role)) {
    return res.status(400).send("role invalide");
  }
  db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, req.params.id);
  res.json({ success: true });
});

router.get("/api/admin/logs", checkAuth, checkAdmin, (req, res) => {
  const logs = db
    .prepare("SELECT id, username, role, timestamp FROM logs ORDER BY id DESC")
    .all();
  res.json(logs);
});

router.get("/api/admin/audit-logs", checkAuth, checkAdmin, (req, res) => {
  const auditLogs = db
    .prepare("SELECT id, username, action, ip_address, user_agent, timestamp FROM connexions_audit ORDER BY id DESC")
    .all();
  res.json(auditLogs);
});

module.exports = router;
