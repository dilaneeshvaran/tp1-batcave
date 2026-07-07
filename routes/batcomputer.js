const express = require("express");
const path = require("path");
const fs = require("fs");
const db = require("../config/db");
const checkAuth = require("../middlewares/checkAuth");
const isAuthenticated = require("../middlewares/authCheck");
const check2FA = require("../middlewares/check2FA");

const router = express.Router();

function insertLog(user) {
  db.prepare(
    "INSERT INTO logs (username, role, timestamp) VALUES (?, ?, ?)",
  ).run(user.username, user.role, new Date().toISOString());
}

router.get("/bat-computer", isAuthenticated, (req, res) => {
  insertLog(req.user);
  const filePath = path.join(__dirname, "../views/bat-computer.html");
  fs.readFile(filePath, "utf8", (err, html) => {
    if (err) {
      return res.status(500).send("erreur lors du chargement du tableau de bord");
    }
    const personalizedHtml = html.replace(
      '<div class="me"></div>',
      `<div class="me">Bienvenue, Justicier, ${req.user.username}!</div>`
    );
    res.send(personalizedHtml);
  });
});

router.get("/api/secrets", checkAuth, (req, res) => {
  insertLog(req.user);
  res.json([
    { name: "Batarang", desc: "Arme de jet", icon: "fa-shuriken" },
    { name: "Batmobile", desc: "vehicule de batman", icon: "fa-car" },
    { name: "Cape", desc: "Permet de planer", icon: "fa-cape" },
    {
      name: "Bat-Signal",
      desc: "Projecteur pour appeler batman",
      icon: "fa-light",
    },
    { name: "Gants", desc: "gants avec des griffes", icon: "fa-hand" },
    { name: "Bat-Grenade", desc: "Grenade explosive", icon: "fa-bomb" },
  ]);
});

router.post("/api/reports", checkAuth, (req, res) => {
  const { message } = req.body;
  const user_id = req.user.id;
  try {
    const insert = db.prepare(
      "INSERT INTO reports (message, user_id) VALUES (?, ?)",
    );
    insert.run(message, user_id);
    res.status(201).send("report saved");
  } catch (err) {
    res.status(500).send("error saving report");
  }
});

router.get("/api/reports", checkAuth, (req, res) => {
  try {
    const reports = db
      .prepare(
        `
      SELECT reports.id, reports.message, reports.user_id, users.username 
      FROM reports 
      JOIN users ON reports.user_id = users.id
    `,
      )
      .all();
    res.json(reports);
  } catch (err) {
    res.status(500).send("error fetching reports");
  }
});

// protected command center endpoint
router.get("/api/user/secret-batmobile", checkAuth, check2FA, (req, res) => {
  insertLog(req.user);
  res.json({
    message: "Système de contrôle de la Batmobile déverrouillé.",
    status: "PRÊT",
    location: "Batcave (secteur B-4)",
    weapons: {
      batarangs: "Armé",
      lasers: "Veille",
      grapple: "Prêt",
    },
    engine: {
      temperature: "95°C",
      fuel: "78%",
      thrusters: "Inactif"
    },
    criticalCommandToken: "BAT-SECRET-COMMAND-EXECUTE-9912"
  });
});

module.exports = router;
