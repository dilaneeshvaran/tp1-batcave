const db = require("../config/db");

const sessionSecurity = (req, res, next) => {
  if (req.session && req.session.user) {
    const sessionIp = req.session.ip;
    const sessionUserAgent = req.session.userAgent;

    const currentIp = req.ip;
    const currentUserAgent = req.headers["user-agent"];

    if (sessionIp && sessionUserAgent) {
      if (sessionIp !== currentIp || sessionUserAgent !== currentUserAgent) {
        console.warn(
          `security alert changement suspect d'appareil ou d'adresse IP en cours de session pour l'utilisateur : ${req.session.user.username}. ip attendue: ${sessionIp}, ip actuelle: ${currentIp}. user-agent attendu: ${sessionUserAgent}, user-agent actuel: ${currentUserAgent}`
        );

        // audit log for fraud attempt (fingerprint mismatch)
        const username = req.session.user.username;
        try {
          db.prepare(
            "INSERT INTO connexions_audit (username, action, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, ?)"
          ).run(username, "FRAUD", currentIp, currentUserAgent || "", new Date().toISOString());
        } catch (auditErr) {
          console.error("failed to log FRAUD event", auditErr);
        }

        return req.session.destroy((err) => {
          res.clearCookie("bat_identity");
          return res
            .status(403)
            .send(
              "<script>alert('accès bloqué : changement suspect d'appareil ou d'adresse ip détecté. '); window.location.href = '/auth/login';</script>"
            );
        });
      }
    }
  }
  next();
};

module.exports = sessionSecurity;
