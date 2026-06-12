require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SqliteStore = require("better-sqlite3-session-store")(session);
const db = require("./config/db");
const authRouter = require("./routes/auth");
const batcomputerRouter = require("./routes/batcomputer");
const adminRouter = require("./routes/admin");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    store: new SqliteStore({
      client: db,
      expired: {
        clear: true,
        intervalMs: 900000, // cleanup expired sessions every 15 mins
      },
    }),
    name: "bat_identity",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      maxAge: 1800000,
    },
  })
);

// Mount entity routers
app.use("/", authRouter);
app.use("/", batcomputerRouter);
app.use("/", adminRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server running at http://localhost:${PORT}`);
});
