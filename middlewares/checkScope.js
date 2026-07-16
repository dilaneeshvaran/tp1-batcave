function checkScope(requiredScope) {
  return (req, res, next) => {
    const scopes = req.user && Array.isArray(req.user.scopes) ? req.user.scopes : [];
    if (!scopes.includes(requiredScope)) {
      return res.status(403).json({
        error: "privileges insuffisants pour cette action.",
        requiredScope,
      });
    }
    next();
  };
}

module.exports = checkScope;
