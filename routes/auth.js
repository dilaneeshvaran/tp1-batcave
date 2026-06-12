const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const db = require("../config/db");
const checkAuth = require("../middlewares/checkAuth");
const { isBlocked, recordFailure, recordSuccess } = require("../middlewares/loginLimiter");

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

router.get("/auth/login", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/login.html"));
});

router.post("/auth/login", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("champs requis manquants");
  }

  const { blocked, remainingMs } = isBlocked(username);
  if (blocked) {
    const remainingSec = Math.ceil(remainingMs / 1000);
    return res
      .status(429)
      .send(
        `<script>alert('trop de tentatives... réessayez dans ${remainingSec} secondes'); window.location.href = '/auth/login';</script>`,
      );
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);

  if (user && (await bcrypt.compare(password, user.password_hash))) {
    recordSuccess(username);

    // regenerate session to prevent session fixation attack
    req.session.regenerate((err) => {
      if (err) return next(err);
      // 1. Stocker l'email ou le username dans la nouvelle session :
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
      };
      req.session.ip = req.ip;
      req.session.userAgent = req.headers["user-agent"];
      // 2. Sauvegarder explicitement : req.session.save()
      req.session.save((err) => {
        if (err) return next(err);
        // 3. Rediriger l'utilisateur vers le tableau de bord (/bat-computer)
        res.redirect("/bat-computer");
      });
    });
  } else {
    recordFailure(username);
    const { blocked: nowBlocked, remainingMs: newRemainingMs } =
      isBlocked(username);
    if (nowBlocked) {
      const remainingSec = Math.ceil(newRemainingMs / 1000);
      return res
        .status(429)
        .send(
          `<script>alert('trop de tentative detectée, compte bloqué pendant ${remainingSec} seconde'); window.location.href = '/auth/login';</script>`,
        );
    }
    return res
      .status(401)
      .send(
        "<script>alert('identifiants invalides'); window.location.href = '/auth/login';</script>",
      );
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
  req.session.destroy((err) => {
    res.clearCookie("bat_identity");
    res.setHeader("WWW-Authenticate", 'Basic realm="Administration"');
    return res.status(401).json({ message: "logged out" });
  });
});

router.get("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie("bat_identity");
    res.redirect("/auth/login");
  });
});

module.exports = router;
