const { verifyAndRefreshTokens } = require("./tokenAuth");

const isAuthenticated = (req, res, next) => {
  if (verifyAndRefreshTokens(req, res)) {
    return next();
  }
  res.status(401);
  return res.send(
    "<script>alert('authentification requise'); window.location.href = '/auth/login';</script>"
  );
};

isAuthenticated.isAuthenticated = isAuthenticated;
module.exports = isAuthenticated;
