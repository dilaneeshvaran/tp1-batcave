const jwt = require("jsonwebtoken");
const db = require("../config/db");

const sessionSecurity = (req, res, next) => {
  const token = req.cookies.access_token;
  if (token) {
    try {
      const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
      // verify the signature but not expire date bcoz of refresh token
      const payload = jwt.verify(token, jwtSecret, { ignoreExpiration: true });
      
      const sessionIp = payload.ip;
      const sessionUserAgent = payload.userAgent;

      const currentIp = req.ip;
      const currentUserAgent = req.headers["user-agent"];

      if (sessionIp && sessionUserAgent) {
        if (sessionIp !== currentIp || sessionUserAgent !== currentUserAgent) {
          console.warn(
            `security alert changement suspect d'appareil ou d'adresse IP en cours de session pour l'utilisateur : ${payload.username}. ip attendue: ${sessionIp}, ip actuelle: ${currentIp}. user-agent attendu: ${sessionUserAgent}, user-agent actuel: ${currentUserAgent}`
          );

          // audit log for fraud attempt (fingerprint mismatch)
          const username = payload.username;
          try {
            db.prepare(
              "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
            ).run(username, "FRAUD", currentIp, currentUserAgent || "", new Date().toISOString());
          } catch (auditErr) {
            console.error("failed to log FRAUD event", auditErr);
          }

          // delete refresh token to block hijacked session
          const refreshToken = req.cookies.refresh_token;
          if (refreshToken) {
            try {
              db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
            } catch (err) {
              console.error("failed to delete compromised refresh token", err);
            }
          }

          res.clearCookie("access_token");
          res.clearCookie("refresh_token");
          
          return res
            .status(403)
            .send(
              "<script>alert('accès bloqué : changement suspect d\\'appareil ou d\\'adresse ip détecté. '); window.location.href = '/auth/login';</script>"
            );
        }
      }
    } catch (err) {
      console.warn("Invalid access token in sessionSecurity check", err.message);
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
    }
  }
  next();
};

module.exports = sessionSecurity;
