const jwt = require("jsonwebtoken");
const db = require("../config/db");

const verifyAndRefreshTokens = (req, res) => {
  const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
  
  //  checking access token
  let accessToken = req.cookies.access_token || req.cookies.accessToken;
  
  // accept bearer token transmission from authorization header
  const authHeader = req.headers.authorization;
  if (!accessToken && authHeader && authHeader.startsWith("Bearer ")) {
    accessToken = authHeader.split(" ")[1];
  }

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
        if (row.used === 1) {
          console.warn(`[SECURITY WARNING] Reuse of refresh token detected in middleware for user ID: ${row.user_id}. Revoking all sessions.`);
          db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").run(row.user_id);
          res.clearCookie("access_token");
          res.clearCookie("accessToken");
          res.clearCookie("refresh_token");
          res.clearCookie("refreshToken");
          return false;
        }

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
          let is2FAVerified = false;
          if (accessToken) {
            try {
              const decoded = jwt.verify(accessToken, jwtSecret, { ignoreExpiration: true });
              if (decoded && decoded.is2FAVerified === true) {
                is2FAVerified = true;
              }
            } catch (err) {
              console.log("echec de la verification de l'ancien access token pour l'heritage 2fa:", err.message);
            }
          }

          const tokenPayload = {
            id: user.id,
            username: user.username,
            role: user.role,
            ip: req.ip,
            userAgent: req.headers["user-agent"] || "",
            is2FAVerified,
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

          res.setHeader("X-Token-Refreshed", "true");
          console.log(`token d'accès rafraichi de manière transparente pour l'utilisateur : ${user.username} (2fa: ${is2FAVerified})`);

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
