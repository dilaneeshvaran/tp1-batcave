const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const QRCode = require("qrcode");
const { authenticator } = require("@otplib/preset-v11");
const db = require("../config/db");
const checkAuth = require("../middlewares/checkAuth");
const checkScope = require("../middlewares/checkScope");
const { getScopesForRole } = require("../middlewares/scopes");
const { isBlocked, recordFailure, recordSuccess } = require("../middlewares/loginLimiter");

const router = express.Router();

const cookieOptions = {
  httpOnly: true,
  secure: false,
  sameSite: "strict",
};

const ACCESS_TOKEN_TTL = "15m";
const ACCESS_TOKEN_MAX_AGE = 15 * 60 * 1000;
const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

function clearAuthCookies(res) {
  res.clearCookie("accessToken", cookieOptions);
  res.clearCookie("refreshToken", cookieOptions);
}

// temporary inmemory store for 2fa validation code
const twoFactorCodes = new Map();

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

router.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "champs requis manquants" });
  }

  const { blocked, remainingMs } = isBlocked(username);
  if (blocked) {
    const remainingSec = Math.ceil(remainingMs / 1000);
    return res.status(429).json({
      error: `trop de tentatives, reessayez dans ${remainingSec} secondes`,
    });
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    recordFailure(username);
    const { blocked: nowBlocked, remainingMs: newRemainingMs } =
      isBlocked(username);
    if (nowBlocked) {
      const remainingSec = Math.ceil(newRemainingMs / 1000);
      return res.status(429).json({
        error: `trop de tentatives, compte bloque pendant ${remainingSec} secondes`,
      });
    }
    return res.status(401).json({ error: "identifiants invalides" });
  }

  recordSuccess(username);

  if (user.two_factor_enabled === 1) {
    return res.status(200).json({
      requires2FA: true,
      username: user.username,
      message: "identifiants valide! saisissez votre code 2fa",
    });
  }

  const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
  const tokenPayload = {
    id: user.id,
    username: user.username,
    role: user.role,
    ip: req.ip,
    userAgent: req.headers["user-agent"] || "",
    is2FAVerified: false,
    scopes: getScopesForRole(user.role),
  };

  const accessToken = jwt.sign(tokenPayload, jwtSecret, {
    expiresIn: ACCESS_TOKEN_TTL,
  });

  const refreshToken = crypto.randomBytes(40).toString("hex");
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_MAX_AGE).toISOString();

  db.prepare(
    "INSERT INTO refresh_tokens (token, user_id, expires_at, created_at, is_used) VALUES (?, ?, ?, ?, 0)"
  ).run(refreshToken, user.id, expiresAt, new Date().toISOString());

  res.cookie("accessToken", accessToken, {
    ...cookieOptions,
    maxAge: ACCESS_TOKEN_MAX_AGE,
  });

  res.cookie("refreshToken", refreshToken, {
    ...cookieOptions,
    maxAge: REFRESH_TOKEN_MAX_AGE,
  });

  try {
    db.prepare(
      "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
    ).run(
      user.username,
      "LOGIN",
      req.ip,
      req.headers["user-agent"] || "",
      new Date().toISOString(),
    );
  } catch (auditErr) {
    console.error("failed to log successful login", auditErr);
  }

  return res.status(200).json({
    success: true,
    message: "conextion reussie",
  });
});

router.post("/api/verify-2fa", async (req, res) => {
  try {
    const { username, code } = req.body;

    if (!username || !code) {
      return res.status(400).json({ error: "username et code requis." });
    }

    const user = db
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username.trim());

    if (!user || user.two_factor_enabled !== 1 || !user.two_factor_secret) {
      return res.status(401).json({ error: "2FA non disponible pour cet utilisateur." });
    }

    const isValid = authenticator.check(String(code).trim(), user.two_factor_secret);
    if (!isValid) {
      return res.status(401).json({ error: "code 2FA invalide ou expire." });
    }

    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role,
      ip: req.ip,
      userAgent: req.headers["user-agent"] || "",
      is2FAVerified: false,
      scopes: getScopesForRole(user.role),
    };

    const accessToken = jwt.sign(tokenPayload, jwtSecret, {
      expiresIn: ACCESS_TOKEN_TTL,
    });

    const refreshToken = crypto.randomBytes(40).toString("hex");
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_MAX_AGE).toISOString();

    db.prepare(
      "INSERT INTO refresh_tokens (token, user_id, expires_at, created_at, is_used) VALUES (?, ?, ?, ?, 0)"
    ).run(refreshToken, user.id, expiresAt, new Date().toISOString());

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: ACCESS_TOKEN_MAX_AGE,
    });

    res.cookie("refreshToken", refreshToken, {
      ...cookieOptions,
      maxAge: REFRESH_TOKEN_MAX_AGE,
    });

    try {
      db.prepare(
        "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
      ).run(
        user.username,
        "LOGIN",
        req.ip,
        req.headers["user-agent"] || "",
        new Date().toISOString(),
      );
    } catch (auditErr) {
      console.error("failed to log successful login", auditErr);
    }

    return res.status(200).json({
      success: true,
      message: "connexion reussie.",
    });
  } catch (err) {
    console.error("erreur verify-2fa", err);
    return res.status(500).json({ error: "erreur interne." });
  }
});

router.get(
  ["/api/me", "/api/user/me"],
  checkAuth,
  checkScope("computers:read"),
  (req, res) => {
    res.json({
      username: req.user.username,
      id: req.user.id,
      role: req.user.role,
      scopes: req.user.scopes || [],
    });
  },
);

router.post("/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  let username = null;

  const token = req.cookies.accessToken;
  if (token) {
    try {
      const decoded = jwt.decode(token);
      if (decoded && decoded.username) {
        username = decoded.username;
      }
    } catch (e) {}
  }

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

  clearAuthCookies(res);
  return res.status(200).json({ success: true, message: "logged out" });
});

router.get("/auth/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  let username = null;

  const token = req.cookies.accessToken;
  if (token) {
    try {
      const decoded = jwt.decode(token);
      if (decoded && decoded.username) {
        username = decoded.username;
      }
    } catch (e) {}
  }

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

  clearAuthCookies(res);
  res.redirect("/auth/login");
});

router.post("/api/auth/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token missing" });
  }

  try {
    const row = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(refreshToken);
    if (!row) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    if (row.is_used === 1) {
      const user = db.prepare("SELECT username FROM users WHERE id = ?").get(row.user_id);
      console.warn(
        `[SECURITY] rejeu refresh token detecte pour user_id=${row.user_id}. revocation de toutes les sessions.`
      );
      db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").run(row.user_id);
      if (user) {
        try {
          db.prepare(
            "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
          ).run(
            user.username,
            "TOKEN_REUSE",
            req.ip,
            req.headers["user-agent"] || "",
            new Date().toISOString(),
          );
        } catch (auditErr) {
          console.error("failed to log TOKEN_REUSE", auditErr);
        }
      }
      clearAuthCookies(res);
      return res.status(401).json({
        error: "session compromise, tous les appareils ont ete deconnectes. reconnexion MFA requise.",
      });
    }

    const isExpired = new Date(row.expires_at) < new Date();
    if (isExpired) {
      db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
      clearAuthCookies(res);
      return res.status(401).json({ error: "Refresh token expired" });
    }

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(row.user_id);
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    db.prepare("UPDATE refresh_tokens SET is_used = 1 WHERE token = ?").run(refreshToken);

    const newRefreshToken = crypto.randomBytes(40).toString("hex");
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_MAX_AGE).toISOString();

    db.prepare(
      "INSERT INTO refresh_tokens (token, user_id, expires_at, created_at, is_used) VALUES (?, ?, ?, ?, 0)"
    ).run(newRefreshToken, user.id, expiresAt, new Date().toISOString());

    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;

    let is2FAVerified = false;
    const oldAccessToken = req.cookies.accessToken;
    if (oldAccessToken) {
      try {
        const decoded = jwt.verify(oldAccessToken, jwtSecret, { ignoreExpiration: true });
        if (decoded && decoded.is2FAVerified === true) {
          is2FAVerified = true;
        }
      } catch (err) {
        console.log("echec de la verification de l'ancien access token pour l'heritage 2fa lors du refresh:", err.message);
      }
    }

    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role,
      ip: req.ip,
      userAgent: req.headers["user-agent"] || "",
      is2FAVerified,
      scopes: getScopesForRole(user.role),
    };

    const accessToken = jwt.sign(tokenPayload, jwtSecret, { expiresIn: ACCESS_TOKEN_TTL });

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: ACCESS_TOKEN_MAX_AGE,
    });

    res.cookie("refreshToken", newRefreshToken, {
      ...cookieOptions,
      maxAge: REFRESH_TOKEN_MAX_AGE,
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

router.post("/api/auth/2fa/setup", checkAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const username = req.user.username;

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) {
      return res.status(404).json({ error: "utilisateur non trouve." });
    }

    if (user.two_factor_enabled === 1) {
      return res.status(400).json({ error: "la 2FA est deja activee sur ce compte." });
    }

    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(username, "Batcave", secret);

    db.prepare(
      "UPDATE users SET two_factor_secret = ?, two_factor_enabled = 0 WHERE id = ?"
    ).run(secret, userId);

    const qrCode = await QRCode.toDataURL(otpauthUrl);

    return res.status(200).json({
      qrCode,
      secret,
      message: "scannez le qr code avec votre application d'authentification.",
    });
  } catch (err) {
    console.error("erreur lors de l'initialisation 2fa", err);
    return res.status(500).json({ error: "impossible d'initialiser la 2FA." });
  }
});

router.post("/api/auth/2fa/confirm", checkAuth, (req, res) => {
  try {
    const { code, username } = req.body;

    if (!code || String(code).trim().length !== 6) {
      return res.status(400).json({ error: "code a 6 chiffres requis." });
    }

    let user;
    if (username) {
      user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
    } else {
      user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    }

    if (!user) {
      return res.status(404).json({ error: "utilisateur non trouve." });
    }

    if (user.id !== req.user.id) {
      return res.status(403).json({ error: "action non autorisee." });
    }

    if (user.two_factor_enabled === 1) {
      return res.status(400).json({ error: "la 2FA est deja activee." });
    }

    if (!user.two_factor_secret) {
      return res.status(400).json({ error: "aucune initialisation 2FA en cours. appelez d'abord /api/auth/2fa/setup." });
    }

    const isValid = authenticator.check(String(code).trim(), user.two_factor_secret);
    if (!isValid) {
      return res.status(401).json({ error: "code 2FA invalide ou expire." });
    }

    db.prepare("UPDATE users SET two_factor_enabled = 1 WHERE id = ?").run(user.id);

    return res.status(200).json({
      success: true,
      message: "2FA activee avec succes.",
    });
  } catch (err) {
    console.error("erreur lors de la confirmation 2fa", err);
    return res.status(500).json({ error: "impossible de confirmer la 2FA." });
  }
});

router.post("/api/auth/2fa/request", checkAuth, (req, res) => {
  try {
    const userId = req.user.id;
    const username = req.user.username;
    
    // generate 6 digit random code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    
    twoFactorCodes.set(userId, { code, expiresAt });
    
    console.log(`\n==================================================`);
    console.log(`[ALFRED 2FA] CODE GENERE POUR : ${username} : ${code}`);
    console.log(`==================================================\n`);
    
    return res.status(200).json({
      message: "code de securite envoye par alfred (consultez la console du serveur)."
    });
  } catch (err) {
    console.error("erreur lors de la demande 2fa", err);
    return res.status(500).json({ error: "impossible de generer le code de securite." });
  }
});

// route to verify the 2fa code and obtain a jwt access token with is2faverified = true
router.post("/api/auth/2fa/verify", checkAuth, (req, res) => {
  try {
    const userId = req.user.id;
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: "code de validation requis." });
    }
    
    const record = twoFactorCodes.get(userId);
    if (!record) {
      return res.status(400).json({ error: "aucun code n'a été demandé pour cet utilisateur." });
    }
    
    if (Date.now() > record.expiresAt) {
      twoFactorCodes.delete(userId);
      return res.status(400).json({ error: "le code a expiré. veuillez en demander un nouveau." });
    }
    
    if (record.code !== code.trim()) {
      return res.status(400).json({ error: "code incorrect. veuillez réessayer." });
    }
    
    // success: remove code from cache
    twoFactorCodes.delete(userId);
    
    // generate upgraded jwt access token (is2faverified: true)
    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    const tokenPayload = {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      ip: req.ip,
      userAgent: req.headers["user-agent"] || "",
      is2FAVerified: true,
      scopes: getScopesForRole(req.user.role),
    };

    const accessToken = jwt.sign(tokenPayload, jwtSecret, { expiresIn: ACCESS_TOKEN_TTL });

    res.cookie("accessToken", accessToken, {
      ...cookieOptions,
      maxAge: ACCESS_TOKEN_MAX_AGE,
    });

    return res.status(200).json({
      success: true,
      message: "double validation reussie ! acces accorde aux commandes critiques."
    });
  } catch (err) {
    console.error("erreur lors de la verification 2fa", err);
    return res.status(500).json({ error: "une erreur est survenue lors de la validation." });
  }
});

module.exports = router;

