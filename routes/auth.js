const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("../config/db");
const checkAuth = require("../middlewares/checkAuth");

const router = express.Router();

router.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/index.html"));
});

router.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/register.html"));
});

router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (password.length < 8) {
    return res.status(400).send("mdp must be at least 8 characters long");
  }

  const hash = await bcrypt.hash(password, 10);

  try {
    const insert = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    );
    insert.run(username.trim(), hash);
    res.status(201).send("User created successfully");
  } catch (err) {
    res.status(409).send("user already exists");
  }
});

router.get("/api/me", checkAuth, (req, res) => {
  res.json({
    username: req.user.username,
    id: req.user.id,
    role: req.user.role,
  });
});

router.post("/logout", (req, res) => {
  res.setHeader("WWW-Authenticate", 'Basic realm="Administration"');
  return res.status(401).json({ message: "logged out" });
});

module.exports = router;
