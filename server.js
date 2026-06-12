require("dotenv").config();
const express = require("express");
const authRouter = require("./routes/auth");
const batcomputerRouter = require("./routes/batcomputer");
const adminRouter = require("./routes/admin");

const app = express();
app.use(express.json());
app.use(express.static("public"));

// Mount entity routers
app.use("/", authRouter);
app.use("/", batcomputerRouter);
app.use("/", adminRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server running at http://localhost:${PORT}`);
});
