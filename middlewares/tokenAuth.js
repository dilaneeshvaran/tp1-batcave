const jwt = require("jsonwebtoken");

const verifyAndRefreshTokens = (req, res) => {
  const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;

  let accessToken = req.cookies.accessToken;

  const authHeader = req.headers.authorization;
  if (!accessToken && authHeader && authHeader.startsWith("Bearer ")) {
    accessToken = authHeader.split(" ")[1];
  }

  if (!accessToken) {
    return false;
  }

  try {
    const decoded = jwt.verify(accessToken, jwtSecret);
    req.user = decoded;
    return true;
  } catch (err) {
    return false;
  }
};

module.exports = { verifyAndRefreshTokens };
