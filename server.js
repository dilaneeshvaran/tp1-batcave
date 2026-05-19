const express = require("express");
const bcrypt = require("bcrypt");
const db = require("./db");
const checkAuth = require("./middleware/checkAuth");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`server running at http://localhost:${PORT}`);
});

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (password.length < 8) {
    return res.status(400).send("mdp must be at least 8 characters long");
  }

  const hash = await bcrypt.hash(password, 10);

  try {
    const insert = db.prepare(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    );
    insert.run(username.trim(), hash);
    res.status(201).send("User created successfully");
  } catch (err) {
    res.status(409).send("user already exists");
  }
});

app.get("/bat-computer", checkAuth, (req, res) => {
  res.sendFile(__dirname + "/private/bat-computer.html");
});

app.get("/api/secrets", checkAuth, (req, res) => {
  res.json(
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
  );
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/public/register.html");
});

app.get("/api/me", checkAuth, (req, res) => {
  res.json({ username: req.user.username, id: req.user.id });
});

app.post("/api/logout", (req, res) => {
  return res.status(401).send("Logged out");
});
