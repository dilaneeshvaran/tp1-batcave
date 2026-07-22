const { verifyAndRefreshTokens } = require("./tokenAuth");

const isAuthenticated = (req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  if (verifyAndRefreshTokens(req, res)) {
    return next();
  }

  res.status(401);
  return res.send(`
<script>
fetch("/api/auth/refresh", { method: "POST" })
  .then((r) => {
    if (r.ok) {
      console.log("token rafraîchi, rechargement de la page");
      location.reload();
    } else {
      location.href = "/auth/login";
    }
  })
  .catch(() => {
    location.href = "/auth/login";
  });
</script>
`);
};

isAuthenticated.isAuthenticated = isAuthenticated;
module.exports = isAuthenticated;
