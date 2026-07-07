const check2FA = (req, res, next) => {
  if (!req.user || req.user.is2FAVerified !== true) {
    return res.status(403).json({ error: "double validation requise pour acceder aux commandes critiques de la batmobile.", need2FA: true });
  }
  next();
};

module.exports = check2FA;
