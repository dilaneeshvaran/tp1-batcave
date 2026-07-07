const jwt = require("jsonwebtoken");
const db = require("../config/db");

const verifyAndRefreshTokens = (req, res) => {
  const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
  
  //  checking access token
  const accessToken = req.cookies.access_token || req.cookies.accessToken;
  if (accessToken) {
    try {
      const decoded = jwt.verify(accessToken, jwtSecret);
      req.user = decoded;
      return true;
    } catch (err) {
      // access token expired, proceed to refresh token 
      console.log("acccess token verification failed or expired, attempting refresh...");
    }
  }

  // checking refresh token
  const refreshToken = req.cookies.refresh_token || req.cookies.refreshToken;
  if (refreshToken) {
    try {
      const row = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(refreshToken);
      if (row) {
        const isExpired = new Date(row.expires_at) < new Date();
        if (isExpired) {
          // clean up expired refresh token
          db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
          res.clearCookie("access_token");
          res.clearCookie("accessToken");
          res.clearCookie("refresh_token");
          res.clearCookie("refreshToken");
          return false;
        }

        // fetch user from database to ensure they still exist
        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(row.user_id);
        if (user) {
          const tokenPayload = {
            id: user.id,
            username: user.username,
            role: user.role,
            ip: req.ip,
            userAgent: req.headers["user-agent"] || "",
          };

          const newAccessToken = jwt.sign(tokenPayload, jwtSecret, { expiresIn: "15s" });

          // set new access token cookie
          res.cookie("access_token", newAccessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 1000,
          });

          res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 15 * 1000,
          });

          req.user = tokenPayload;
          return true;
        }
      }
    } catch (dbErr) {
      console.error("Error during refresh token lookup", dbErr);
    }
  }

  return false;
};

module.exports = { verifyAndRefreshTokens };
