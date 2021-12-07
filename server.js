import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";
import UserModel from "./models/User.js";
import bcrypt from "bcrypt";

dotenv.config();

const saltRounds = Number(process.env.SALT);

mongoose.connect(process.env.MONGO_URI);

const app = express();
const PORT = 3003;

// const user = await User.findOne({ login: "anonymousUser" });
// res.json(user);

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET || "tempsecret",
  })
);

app.get("/user", async (req, res) => {
  const user = await UserModel.find();
  res.json(user);
});

app.post("/login", async (req, res) => {
  const login = req.body.login;
  // const password = req.body.password;
  console.log(login);
  let user = await UserModel.findOne({ login });
  if (!user) {
    user = await UserModel.findOne({ login: "anonymousUser" });
  }
  req.session.user = user;
  req.session.save();
  res.json(user);
});

app.post("/signup", async (req, res) => {
  const frontendUser = req.body.user;
  // console.log(frontendUser);
  if (
    frontendUser.login.trim() === "" ||
    frontendUser.password1.trim() === "" ||
    frontendUser.password1 !== frontendUser.password2
  ) {
    res.sendStatus(403);
  } else {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(frontendUser.password1, salt);
    const backendUser = {
      firstName: frontendUser.firstName,
      lastName: frontendUser.lastName,
      login: frontendUser.login,
      email: frontendUser.email,
      hash,
      accessGroups: "loggedInUsers, notYetApprovedUsers",
    };
    const dbuser = await UserModel.create(backendUser);
    res.json({
      userAdded: dbuser,
    });
  }
});

app.get("/currentuser", async (req, res) => {
  let user = req.session.user;
  if (!user) {
    user = await UserModel.findOne({ login: "anonymousUser" });
  }
  res.json(user);
});


app.get("/notyetapprovedusers", async (req, res) => {
	const users = await UserModel.find({ "accessGroups": { "$regex": "notYetApprovedUsers", "$options": "i" } });
	res.json({
		users
	});
});

app.get("/logout", async (req, res) => {
  req.session.destroy();
  const user = await UserModel.findOne({ login: "anonymousUser" });
  res.json(user);
});

app.listen(PORT, (req, res) => {
  console.log(`API listening on port http://localhost:${PORT}`);
});
