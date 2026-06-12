const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.user) {
    req.user = req.session.user;
    return next();
  }
  res.status(401);
  return res.send(
    "<script>alert('authentification requise'); window.location.href = '/auth/login';</script>"
  );
};

isAuthenticated.isAuthenticated = isAuthenticated;
module.exports = isAuthenticated;
