const express = require("express");
const path = require("path");
const db = require("../config/db");
const checkAuth = require("../middlewares/checkAuth");

const router = express.Router();

function insertLog(user) {
  db.prepare(
    "INSERT INTO logs (username, role, timestamp) VALUES (?, ?, ?)",
  ).run(user.username, user.role, new Date().toISOString());
}

router.get("/bat-computer", checkAuth, (req, res) => {
  insertLog(req.user);
  res.sendFile(path.join(__dirname, "../views/bat-computer.html"));
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

module.exports = router;
