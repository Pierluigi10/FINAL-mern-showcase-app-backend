import express from "express";
// import session from "cookie-session";
import session from "express-session";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";
import UserModel from "./models/User.js";
import bcrypt from "bcrypt";
import colors from "colors";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3003;
app.set("trust proxy", 1); // allow / trust Heroku proxy to forward secure cookies
app.use(express.json());

const saltRounds = Number(process.env.SALTROUNDS);

const mongoConnectString = process.env.MONGO_URI;
mongoose
  .connect(mongoConnectString, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log(`MongoDB Connected`.cyan.bold))
  .catch((err) => console.log(`Error: ${err.message}`.red.bold));

const userIsInGroup = (user, accessGroup) => {
  const accessGroupArray = user.accessGroups.split(",").map((m) => m.trim());
  return accessGroupArray.includes(accessGroup);
};

app.use(
  cors({
    origin: process.env.ORIGIN_URL || "http://localhost:3000",
    credentials: true, // accept incoming cookies
  })
);

// Configure SESSION COOKIES (=> this will create a cookie in the browser once we set some data into req.session)
app.use(
  session({
    name: "sessId",
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
      httpOnly: true, // httpOnly => cookie can just be written from API and not by Javascript
      maxAge: 60 * 1000 * 30, // 30 minutes of inactivity
      // sameSite: "none", // allow cookies transfered from OTHER origin
      // secure: true, // allow cookies to be set just via HTTPS
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      secure: process.env.NODE_ENV === "production",
    },
  })
);

app.use(cookieParser());

app.get("/user", async (req, res) => {
  const user = await UserModel.find();
  res.json(user);
});

//bcrypt.compare('password', theHash).then(result => console.log(result));
app.post("/login", async (req, res) => {
  console.log(req.body);
  const login = req.body.login;
  const password = req.body.password;
  console.log(login);
  let user = await UserModel.findOne({ login });
  if (!user) {
    user = await UserModel.findOne({ login: "anonymousUser" });
  } else {
    bcrypt.compare(password, user.hash).then((passwordIsOk) => {
      if (passwordIsOk) {
        req.session.user = user;
        req.session.save();
        res.json(user);
      } else {
        res.sendStatus(403);
      }
    });
  }
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

//approve the users
app.post("/approveuser", async (req, res) => {
  const id = req.body.id;
  let user = req.session.user;
  console.log(id, user);
  if (!user) {
    console.log("1111");
    res.sendStatus(403);
  } else {
    if (!userIsInGroup(user, "admins")) {
      console.log("2222");
      res.sendStatus(403);
    } else {
      console.log("333");
      const updateResult = await UserModel.findOneAndUpdate(
        { _id: new mongoose.Types.ObjectId(id) },
        { $set: { accessGroups: "loggedInUsers,members" } },
        { new: true }
      );
      res.json({
        result: updateResult,
      });
    }
  }
});

// show all approved users
app.get("/approveuser", async (req, res) => {
  const users = await UserModel.find({
    accessGroups: { $regex: "members", $options: "i" },
  });
  res.json({
    users,
  });
});

// show all not yet approved users
app.get("/notyetapprovedusers", async (req, res) => {
  const users = await UserModel.find({
    accessGroups: { $regex: "notYetApprovedUsers", $options: "i" },
  });
  res.json({
    users,
  });
});

app.get("/logout", async (req, res) => {
  req.session.destroy();
  const user = await UserModel.findOne({ login: "anonymousUser" });
  res.json(user);
});

app.listen(PORT, (req, res) => {
  console.log((("API Listening on port ").yellow) + ((`http://localhost:${PORT}`).yellow.underline.bold));
});
