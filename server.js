require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const db = require("./config/db");
const authRouter = require("./routes/auth");
const batcomputerRouter = require("./routes/batcomputer");
const adminRouter = require("./routes/admin");
const sessionSecurity = require("./middlewares/sessionSecurity");

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "img-src": ["'self'", "data:"],
      },
    },
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());

app.use(sessionSecurity);

// Mount entity routers
app.use("/", authRouter);
app.use("/", batcomputerRouter);
app.use("/", adminRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server running at http://localhost:${PORT}`);
});
