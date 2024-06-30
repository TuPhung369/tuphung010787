// server.js
import express from "express";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import bodyParser from "body-parser";
import router1 from "./apiRouter.js";
import accountRouter from "./routers/account.js";
import AccountModel from "./models/account.js";

dotenv.config(); // This loads the variables in .env into process.env

const app = express();
const port = process.env.PORT;

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  const pathHome = path.join(__dirname, "home.html");
  console.log(pathHome);
  res.sendFile(pathHome);
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Example middleware functions (not currently used)
// const checkLogin = (req, res, next) => {
//   if (Login) {
//     req.user = User;
//     next();
//   } else {
//     res.json("Please login first!");
//   }
// };

// const checkAdmin = (req, res, next) => {
//   if (req.user.role === "Admin") {
//     next();
//   } else {
//     res.json("Please login as admin!");
//   }
// };

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  AccountModel.findOne({ username: username })
    .then((data) => {
      if (data) {
        console.log("Account already exists:", data); // Log the data
        res.json("Account already exists");
      } else {
        return AccountModel.create({
          username: username,
          password: password,
        });
      }
    })
    .then((data) => {
      console.log("Account created successfully:", data.username); // Log the data
      res.json("Account created successfully");
    })
    .catch((err) => {
      console.error("Error checking account:", err); // Log the error
      res.status(500).json("Error checking account");
    });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  AccountModel.findOne({ username: username, password: password })
    .then((data) => {
      if (data) {
        console.log("Login successful:", data.username); // Log the data
        res.json("Login successful");
      } else {
        console.log("Login failed"); // Log the data
        res.status(400).json("Login failed");
      }
    })
    .catch((err) => {
      console.error("Error checking account:", err); // Log the error
      res.status(500).json("Error checking account");
    });
});

// app.get(
//   "/",
//   (req, res, next) => {
//     console.log("Hello from middleware 1");
//     next();
//   },
//   (req, res, next) => {
//     console.log("Hello from middleware 2");
//     next();
//   },
//   (req, res, next) => {
//     console.log("Hello from middleware 3");
//     res.send("Ending");
//   }
// );

// Uncommented middleware usage example
// app.use("/api/v1/", checkLogin, checkAdmin, router1);
app.use("/api/v1/", router1);
app.use("/api/account/", accountRouter);
app.listen(port, () => {
  console.log(`Server started on ${port}`);
});
