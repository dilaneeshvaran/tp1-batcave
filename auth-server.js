require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./config/auth-db");

const app = express();
const PORT = 4000;
const JWT_SECRET = process.env.SESSION_SECRET || "batcave_oauth_secret_key";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, code_challenge } = req.query;

  if (!client_id || !redirect_uri || !code_challenge) {
    return res.status(400).send("parametres d'autorisation manquants (client_id, redirect_uri, code_challenge requis)");
  }

  res.sendFile(path.join(__dirname, "views/auth-server-login.html"));
});

app.post("/authorize", async (req, res) => {
  const { username, password, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.body;

  if (!username || !password) {
    const errorUrl = `/authorize?client_id=${encodeURIComponent(client_id || "")}&redirect_uri=${encodeURIComponent(redirect_uri || "")}&state=${encodeURIComponent(state || "")}&code_challenge=${encodeURIComponent(code_challenge || "")}&error=invalid_credentials`;
    return res.redirect(errorUrl);
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ? OR email = ?")
    .get(username.trim(), username.trim());

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    const errorUrl = `/authorize?client_id=${encodeURIComponent(client_id || "")}&redirect_uri=${encodeURIComponent(redirect_uri || "")}&state=${encodeURIComponent(state || "")}&code_challenge=${encodeURIComponent(code_challenge || "")}&error=invalid_credentials`;
    return res.redirect(errorUrl);
  }

  const authCode = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO authorization_codes 
    (code, client_id, redirect_uri, code_challenge, code_challenge_method, user_id, expires_at, used) 
    VALUES (?, ?, ?, ?, ?, ?, ?, 0)
  `).run(
    authCode,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method || "S256",
    user.id,
    expiresAt
  );

  const targetUrl = new URL(redirect_uri);
  targetUrl.searchParams.set("code", authCode);
  if (state) targetUrl.searchParams.set("state", state);

  return res.redirect(targetUrl.toString());
});

app.post("/token", (req, res) => {
  const grantType = req.body.grant_type;
  const code = req.body.code;
  const clientId = req.body.client_id;
  const redirectUri = req.body.redirect_uri;
  const codeVerifier = req.body.code_verifier;

  if (grantType !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type", error_description: "grant_type doit etre authorization_code" });
  }

  if (!code || !codeVerifier) {
    return res.status(400).json({ error: "invalid_request", error_description: "param code et code_verifier requis" });
  }

  // Retrieve code from database
  const record = db.prepare("SELECT * FROM authorization_codes WHERE code = ?").get(code);

  if (!record) {
    return res.status(400).json({ error: "invalid_grant", error_description: "code d'autorisation introuvable" });
  }

  if (record.used === 1) {
    return res.status(400).json({ error: "invalid_grant", error_description: "code d'autorisation deja utilisé" });
  }

  if (Date.now() > new Date(record.expires_at).getTime()) {
    return res.status(400).json({ error: "invalid_grant", error_description: "code d'autorisation expiré" });
  }

  if (redirectUri && redirectUri !== record.redirect_uri) {
    return res.status(400).json({ error: "invalid_grant", error_description: "uri de redirection ne correspond pas" });
  }

  const computedChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  if (computedChallenge !== record.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "echec de verification pkce : code_verifier ne correspond pas au code_challenge",
    });
  }

  db.prepare("UPDATE authorization_codes SET used = 1 WHERE id = ?").run(record.id);

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(record.user_id);
  const tokenPayload = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: "USER",
    iss: "http://localhost:4000",
    aud: clientId || "batcave_client",
  };

  const accessToken = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1h" });

  return res.status(200).json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
  });
});

app.get("/userinfo", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized", error_description: "entete authorization bearer manquant" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({
      sub: String(decoded.id),
      name: decoded.username,
      email: decoded.email,
      role: decoded.role,
    });
  } catch (err) {
    return res.status(401).json({ error: "invalid_token", error_description: "jeton jwt expiré ou invalide" });
  }
});

app.listen(PORT, () => {
  console.log(`[batauth] serveur d'autorisation écoutant sur http://localhost:${PORT}`);
});
