const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
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

    // generate jwt access token (15 sec expiry)
    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role,
      ip: req.ip,
      userAgent: req.headers["user-agent"] || "",
    };
    
    const accessToken = jwt.sign(tokenPayload, jwtSecret, { expiresIn: "15s" });

    const refreshToken = crypto.randomBytes(40).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    try {
      db.prepare(
        "INSERT INTO refresh_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
      ).run(refreshToken, user.id, expiresAt, new Date().toISOString());
    } catch (dbErr) {
      console.error("failed to save refresh token", dbErr);
      return next(dbErr);
    }

    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 1000,
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 1000,
    });

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });

    // audit log for successful login
    try {
      db.prepare(
        "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
      ).run(user.username, "LOGIN", req.ip, req.headers["user-agent"] || "", new Date().toISOString());
    } catch (auditErr) {
      console.error("failed to log successful login", auditErr);
    }

    res.redirect("/bat-computer");
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
  const refreshToken = req.cookies.refresh_token || req.cookies.refreshToken;
  let username = null;

  //  get username from access token
  const token = req.cookies.access_token || req.cookies.accessToken;
  if (token) {
    try {
      const decoded = jwt.decode(token);
      if (decoded && decoded.username) {
        username = decoded.username;
      }
    } catch (e) {}
  }

  // fallback username via refresh token before deleting it
  if (!username && refreshToken) {
    try {
      const row = db.prepare(
        "SELECT users.username FROM refresh_tokens JOIN users ON refresh_tokens.user_id = users.id WHERE refresh_tokens.token = ?"
      ).get(refreshToken);
      if (row) {
        username = row.username;
      }
    } catch (e) {
      console.error("failed to query username from refresh token", e);
    }
  }

  if (refreshToken) {
    try {
      db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
    } catch (e) {
      console.error("failed to delete refresh token", e);
    }
  }

  if (username) {
    try {
      db.prepare(
        "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
      ).run(username, "LOGOUT", req.ip, req.headers["user-agent"] || "", new Date().toISOString());
    } catch (auditErr) {
      console.error("failed to log voluntary logout", auditErr);
    }
  }

  res.clearCookie("access_token");
  res.clearCookie("accessToken");
  res.clearCookie("refresh_token");
  res.clearCookie("refreshToken");
  res.setHeader("WWW-Authenticate", 'Basic realm="Administration"');
  return res.status(401).json({ message: "logged out" });
});

router.get("/auth/logout", (req, res) => {
  const refreshToken = req.cookies.refresh_token || req.cookies.refreshToken;
  let username = null;

  // get username from access token
  const token = req.cookies.access_token || req.cookies.accessToken;
  if (token) {
    try {
      const decoded = jwt.decode(token);
      if (decoded && decoded.username) {
        username = decoded.username;
      }
    } catch (e) {}
  }

  // fallback username via refresh token before deleting it
  if (!username && refreshToken) {
    try {
      const row = db.prepare(
        "SELECT users.username FROM refresh_tokens JOIN users ON refresh_tokens.user_id = users.id WHERE refresh_tokens.token = ?"
      ).get(refreshToken);
      if (row) {
        username = row.username;
      }
    } catch (e) {
      console.error("failed to query username from refresh token", e);
    }
  }

  if (refreshToken) {
    try {
      db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
    } catch (e) {
      console.error("failed to delete refresh token", e);
    }
  }

  if (username) {
    try {
      db.prepare(
        "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
      ).run(username, "LOGOUT", req.ip, req.headers["user-agent"] || "", new Date().toISOString());
    } catch (auditErr) {
      console.error("failed to log voluntary logout", auditErr);
    }
  }

  res.clearCookie("access_token");
  res.clearCookie("accessToken");
  res.clearCookie("refresh_token");
  res.clearCookie("refreshToken");
  res.redirect("/auth/login");
});

router.post("/api/auth/refresh", (req, res) => {
  const refreshToken = req.cookies.refresh_token || req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token missing" });
  }

  try {
    const row = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(refreshToken);
    if (!row) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    // reuse detection
    if (row.used === 1) {
      console.warn(`[SECURITY WARNING] Reuse of refresh token detected for user ID: ${row.user_id}. Revoking all sessions.`);
      db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").run(row.user_id);
      res.clearCookie("access_token");
      res.clearCookie("accessToken");
      res.clearCookie("refresh_token");
      res.clearCookie("refreshToken");
      return res.status(401).json({ error: "Compromised session, all devices disconnected." });
    }

    const isExpired = new Date(row.expires_at) < new Date();
    if (isExpired) {
      // clean up expired refresh token
      db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
      res.clearCookie("access_token");
      res.clearCookie("accessToken");
      res.clearCookie("refresh_token");
      res.clearCookie("refreshToken");
      return res.status(401).json({ error: "Refresh token expired" });
    }

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(row.user_id);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    // rotate refresh token: mark current as used, generate new one
    db.prepare("UPDATE refresh_tokens SET used = 1 WHERE token = ?").run(refreshToken);

    const newRefreshToken = crypto.randomBytes(40).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    db.prepare(
      "INSERT INTO refresh_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
    ).run(newRefreshToken, user.id, expiresAt, new Date().toISOString());

    // generate jwt access token (15 sec expiry)
    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role,
      ip: req.ip,
      userAgent: req.headers["user-agent"] || "",
    };

    const accessToken = jwt.sign(tokenPayload, jwtSecret, { expiresIn: "15s" });

    res.cookie("access_token", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 1000,
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 15 * 1000,
    });

    res.cookie("refresh_token", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, 
    });

    return res.status(200).json({ message: "Token refreshed successfully" });
  } catch (err) {
    console.error("Error during token refresh", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/api/auth/change-password", checkAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: "Tous les champs sont requis." });
  }

  try {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "Utilisateur non trouvé." });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: "L'ancien mot de passe est incorrect." });
    }

    // anssi 
    const anssiRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{12,}$/;
    if (!anssiRegex.test(newPassword)) {
      return res.status(400).json({
        error: "nouveau mot de passe ne respecte pas les critères de robustesse anssi (au moins 12 caractères, 1 majuscule, 1 minuscule, 1 chiffre et 1 caractère spécial)."
      });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(newHash, req.user.id);

    return res.status(200).json({ message: "Mot de passe modifié avec succès." });
  } catch (err) {
    console.error("Erreur lors de la modification du mot de passe", err);
    return res.status(500).json({ error: "Une erreur interne est survenue." });
  }
});

module.exports = router;

