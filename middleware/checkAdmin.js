const checkAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== "ADMIN") {
    return res.status(403).send("acces refusec");
  }
  next();
};

module.exports = checkAdmin;
