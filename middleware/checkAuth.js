const bcrypt = require("bcrypt");
const db = require("../db");

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

  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);
  if (user && (await bcrypt.compare(password, user.password_hash))) {
    req.user = user;
    next();
  } else {
    res.setHeader("WWW-Authenticate", 'Basic realm="Administration"');
    return res
      .status(401)
      .send(
        "<script>alert('Invalides identifiants'); window.location.href = '/';</script>",
      );
  }
};

module.exports = checkAuth;
