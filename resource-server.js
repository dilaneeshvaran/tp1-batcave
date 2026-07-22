require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.SESSION_SECRET || "batcave_oauth_secret_key";

app.use(express.json());

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://localhost:3000");
  res.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

function authenticateBearerToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "unauthorized",
      message: "entete authorization bearer manquant",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "token_expired",
        message: "le jeton d'acces a expiré",
      });
    }
    return res.status(401).json({
      error: "invalid_token",
      message: "signature du jeton invalide",
    });
  }
}

app.get("/api/missions", authenticateBearerToken, (req, res) => {
  res.json({
    secretLevel: "TOP SECRET - BATCAVE RESOURCE SERVER (PORT 5000)",
    agent: req.user.username || req.user.email,
    missions: [
      {
        id: "M-01",
        title: "emprisonnement du harley queen",
        target: "joker",
        status: "EN COURS",
        priority: "HAUTE",
      },
      {
        id: "M-02",
        title: "réparation de bat signal",
        target: "sir alfred",
        status: "EN ATTENTE",
        priority: "MOYENNE",
      },
      {
        id: "M-03",
        title: "téléchargement d'un vpn",
        target: "serveur proxy",
        status: "EN COURS",
        priority: "FAIBLE",
      },
    ],
  });
});

app.listen(PORT, () => {
  console.log(`[batresource] serveur de ressources écoutant sur http://localhost:${PORT}`);
});
