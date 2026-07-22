const express = require("express");
const crypto = require("crypto");
const path = require("path");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
const { getScopesForRole } = require("../middlewares/scopes");

const router = express.Router();

const cookieOptions = {
  httpOnly: true,
  secure: false,
  sameSite: "lax",
};

const ACCESS_TOKEN_TTL = "15m";
const ACCESS_TOKEN_MAX_AGE = 15 * 60 * 1000;
const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000;


// generates random verifier
function generatePKCE() {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const state = crypto.randomBytes(16).toString("hex");

  return { codeVerifier, codeChallenge, state };
}

function completeOAuthLogin(req, res, user) {
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

  res.clearCookie("oauth_state");
  res.clearCookie("oauth_verifier");

  try {
    db.prepare(
      "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
    ).run(
      user.username,
      `OAUTH_LOGIN_${user.provider.toUpperCase()}`,
      req.ip,
      req.headers["user-agent"] || "",
      new Date().toISOString()
    );
  } catch (_) {}

  return res.redirect("/bat-computer");
}

router.get("/auth/error", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/auth-error.html"));
});

router.get("/auth/google", (req, res) => {
  const { codeVerifier, codeChallenge, state } = generatePKCE();

  res.cookie("oauth_state", state, { ...cookieOptions, maxAge: 600000 });
  res.cookie("oauth_verifier", codeVerifier, { ...cookieOptions, maxAge: 600000 });

  const googleAuthUrl =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID || "",
      redirect_uri: process.env.GOOGLE_REDIRECT_URI || "http://localhost:3000/auth/google/callback",
      response_type: "code",
      scope: "openid email profile",
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }).toString();

  res.redirect(googleAuthUrl);
});

router.get("/auth/google/callback", async (req, res) => {
  if (req.query.error) {
    res.clearCookie("oauth_state");
    res.clearCookie("oauth_verifier");
    return res.redirect(`/auth/error?error=${encodeURIComponent(req.query.error)}&provider=Google`);
  }

  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;
  const codeVerifier = req.cookies.oauth_verifier;

  if (!state || state !== savedState || !codeVerifier) {
    return res.redirect("/auth/error?error=invalid_state&provider=Google");
  }

  if (!code) {
    return res.redirect("/auth/error?error=missing_code&provider=Google");
  }

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID || "",
        client_secret: process.env.GOOGLE_CLIENT_SECRET || "",
        code: code,
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        redirect_uri: process.env.GOOGLE_REDIRECT_URI || "http://localhost:3000/auth/google/callback",
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.access_token) {
      return res.redirect(`/auth/error?error=${encodeURIComponent(tokenData.error || "token_exchange_failed")}&provider=Google`);
    }

    const profileRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    const provider = "google";
    const providerUserId = String(profile.sub);
    const email = profile.email || null;
    let username = profile.name || profile.email || `google_${providerUserId}`;

    let user = db
      .prepare("SELECT * FROM users WHERE provider = ? AND provider_user_id = ?")
      .get(provider, providerUserId);

    if (!user) {
      let candidateUsername = username;
      const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(candidateUsername);
      if (existingUser) {
        candidateUsername = `${username} (google)`;
      }

      const stmt = db.prepare(
        "INSERT INTO users (username, email, provider, provider_user_id, role) VALUES (?, ?, ?, ?, 'USER')"
      );
      const result = stmt.run(candidateUsername, email, provider, providerUserId);
      user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    }

    return completeOAuthLogin(req, res, user);
  } catch (err) {
    console.error("erreur google auth callback:", err);
    return res.redirect("/auth/error?error=server_error&provider=Google");
  }
});


router.get("/auth/github", (req, res) => {
  const { codeVerifier, codeChallenge, state } = generatePKCE();

  res.cookie("oauth_state", state, { ...cookieOptions, maxAge: 600000 });
  res.cookie("oauth_verifier", codeVerifier, { ...cookieOptions, maxAge: 600000 });

  const githubAuthUrl =
    "https://github.com/login/oauth/authorize?" +
    new URLSearchParams({
      client_id: process.env.GITHUB_CLIENT_ID || "",
      redirect_uri: process.env.GITHUB_REDIRECT_URI || "http://localhost:3000/auth/github/callback",
      scope: "read:user user:email",
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }).toString();

  res.redirect(githubAuthUrl);
});

router.get("/auth/github/callback", async (req, res) => {
  if (req.query.error) {
    res.clearCookie("oauth_state");
    res.clearCookie("oauth_verifier");
    return res.redirect(`/auth/error?error=${encodeURIComponent(req.query.error)}&provider=GitHub`);
  }

  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;
  const codeVerifier = req.cookies.oauth_verifier;

  if (!state || state !== savedState || !codeVerifier) {
    return res.redirect("/auth/error?error=invalid_state&provider=GitHub");
  }

  if (!code) {
    return res.redirect("/auth/error?error=missing_code&provider=GitHub");
  }

  try {
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID || "",
        client_secret: process.env.GITHUB_CLIENT_SECRET || "",
        code: code,
        code_verifier: codeVerifier,
        redirect_uri: process.env.GITHUB_REDIRECT_URI || "http://localhost:3000/auth/github/callback",
      }),
    });

    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.access_token) {
      return res.redirect(`/auth/error?error=${encodeURIComponent(tokenData.error || "token_exchange_failed")}&provider=GitHub`);
    }

    const profileRes = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "User-Agent": "Batcave-App",
      },
    });
    const profile = await profileRes.json();

    let email = profile.email;
    if (!email) {
      try {
        const emailsRes = await fetch("https://api.github.com/user/emails", {
          headers: {
            Authorization: `Bearer ${tokenData.access_token}`,
            "User-Agent": "Batcave-App",
          },
        });
        const emails = await emailsRes.json();
        if (Array.isArray(emails)) {
          const primaryEmail = emails.find((e) => e.primary && e.verified) || emails[0];
          if (primaryEmail) email = primaryEmail.email;
        }
      } catch (_) {}
    }

    const provider = "github";
    const providerUserId = String(profile.id);
    let username = profile.login || profile.name || `github_${providerUserId}`;

    let user = db
      .prepare("SELECT * FROM users WHERE provider = ? AND provider_user_id = ?")
      .get(provider, providerUserId);

    if (!user) {
      let candidateUsername = username;
      const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(candidateUsername);
      if (existingUser) {
        candidateUsername = `${username} (github)`;
      }

      const stmt = db.prepare(
        "INSERT INTO users (username, email, provider, provider_user_id, role) VALUES (?, ?, ?, ?, 'USER')"
      );
      const result = stmt.run(candidateUsername, email, provider, providerUserId);
      user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    }

    return completeOAuthLogin(req, res, user);
  } catch (err) {
    console.error("erreur gh oauth callback:", err);
    return res.redirect("/auth/error?error=server_error&provider=GitHub");
  }
});


router.get("/auth/meta", (req, res) => {
  const { codeVerifier, codeChallenge, state } = generatePKCE();

  res.cookie("oauth_state", state, { ...cookieOptions, maxAge: 600000 });
  res.cookie("oauth_verifier", codeVerifier, { ...cookieOptions, maxAge: 600000 });

  const metaAuthUrl =
    "https://www.facebook.com/v19.0/dialog/oauth?" +
    new URLSearchParams({
      client_id: process.env.META_CLIENT_ID || "",
      redirect_uri: process.env.META_REDIRECT_URI || "http://localhost:3000/auth/meta/callback",
      scope: "email,public_profile",
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    }).toString();

  res.redirect(metaAuthUrl);
});

router.get("/auth/meta/callback", async (req, res) => {
  if (req.query.error || req.query.error_reason) {
    res.clearCookie("oauth_state");
    res.clearCookie("oauth_verifier");
    return res.redirect(`/auth/error?error=${encodeURIComponent(req.query.error || req.query.error_reason)}&provider=Meta`);
  }

  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;
  const codeVerifier = req.cookies.oauth_verifier;

  if (!state || state !== savedState || !codeVerifier) {
    return res.redirect("/auth/error?error=invalid_state&provider=Meta");
  }

  if (!code) {
    return res.redirect("/auth/error?error=missing_code&provider=Meta");
  }

  try {
    const tokenUrl =
      "https://graph.facebook.com/v19.0/oauth/access_token?" +
      new URLSearchParams({
        client_id: process.env.META_CLIENT_ID || "",
        client_secret: process.env.META_CLIENT_SECRET || "",
        code: code,
        code_verifier: codeVerifier,
        redirect_uri: process.env.META_REDIRECT_URI || "http://localhost:3000/auth/meta/callback",
      }).toString();

    const tokenRes = await fetch(tokenUrl);
    const tokenData = await tokenRes.json();

    if (!tokenRes.ok || !tokenData.access_token) {
      return res.redirect(`/auth/error?error=${encodeURIComponent(tokenData.error?.message || "token_exchange_failed")}&provider=Meta`);
    }

    const profileRes = await fetch(
      `https://graph.facebook.com/v19.0/me?fields=id,name,email&access_token=${tokenData.access_token}`
    );
    const profile = await profileRes.json();

    const provider = "facebook";
    const providerUserId = String(profile.id);
    const email = profile.email || null;
    let username = profile.name || `facebook_${providerUserId}`;

    let user = db
      .prepare("SELECT * FROM users WHERE provider = ? AND provider_user_id = ?")
      .get(provider, providerUserId);

    if (!user) {
      let candidateUsername = username;
      const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(candidateUsername);
      if (existingUser) {
        candidateUsername = `${username} (facebook)`;
      }

      const stmt = db.prepare(
        "INSERT INTO users (username, email, provider, provider_user_id, role) VALUES (?, ?, ?, ?, 'USER')"
      );
      const result = stmt.run(candidateUsername, email, provider, providerUserId);
      user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    }

    return completeOAuthLogin(req, res, user);
  } catch (err) {
    console.error("erreur meta oauth callback:", err);
    return res.redirect("/auth/error?error=server_error&provider=Meta");
  }
});

module.exports = router;
