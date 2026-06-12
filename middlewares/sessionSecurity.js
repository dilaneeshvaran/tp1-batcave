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
