const bcrypt = require("bcrypt");
const db = require("../db");
const { isBlocked, recordFailure, recordSuccess } = require("./loginLimiter");

const checkAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Administration"');
    return res
      .status(401)
      .send(
        "<script>alert('Authentification requise'); window.location.href = '/';</script>",
      );
  }
  const base64 = authHeader.split(" ")[1];
  const [username, password] = Buffer.from(base64, "base64")
    .toString()
    .split(":");

  // verify if user is blocked temporarily
  const { blocked, remainingMs } = isBlocked(username);
  if (blocked) {
    const remainingSec = Math.ceil(remainingMs / 1000);
    return res
      .status(429)
      .send(
        `<script>alert('trop de tentatives... réessayez dans${remainingSec} secondes'); window.location.href = '/';</script>`,
      );
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);
  if (user && (await bcrypt.compare(password, user.password_hash))) {
    recordSuccess(username);
    req.user = user;
    next();
  } else {
    recordFailure(username);
    const { blocked: nowBlocked, remainingMs: newRemainingMs } =
      isBlocked(username);
    if (nowBlocked) {
      const remainingSec = Math.ceil(newRemainingMs / 1000);
      return res
        .status(429)
        .send(
          `<script>alert('trop de tentative detectée, compte bloqué pendant ${remainingSec} seconde'); window.location.href = '/';</script>`,
        );
    }
    return res
      .status(401)
      .send(
        "<script>console.log('Invalides identifiants'); alert('Invalides identifiants'); window.location.href = '/';</script>",
      );
  }
};

module.exports = checkAuth;
