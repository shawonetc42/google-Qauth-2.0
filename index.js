require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const MongoStore = require("connect-mongo");
const cors = require("cors"); // CORS প্যাকেজ ইম্পোর্ট করুন

const app = express();

// MongoDB কানেকশন
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// ইউজার স্কিমা এবং মডেল
const userSchema = new mongoose.Schema({
  googleId: String,
  displayName: String,
  email: String,
});

const User = mongoose.model("Userbd", userSchema);

// Passport কনফিগারেশন
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = await new User({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value,
          }).save();
        }

        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS কনফিগারেশন
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000", // পরিবেশ ভ্যারিয়েবল ব্যবহার করুন
    credentials: true, // কুকিজ পাঠানোর অনুমতি দিন
  })
);

// Express সেশন কনফিগারেশন
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 1 দিন (24 ঘণ্টা)
      secure: process.env.NODE_ENV === "production", // HTTPS ব্যবহার করলে true
      httpOnly: true, // JavaScript দ্বারা অ্যাক্সেস প্রতিরোধ
    },
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
    }),
  })
);

// Passport এবং সেশন ইনিশিয়ালাইজ করুন
app.use(passport.initialize());
app.use(passport.session());

// রাউট
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect(process.env.FRONTEND_URL || "http://localhost:3000");
  }
);

app.get("/api/current_user", (req, res) => {
  res.send(req.user);
});

app.get("/api/logout", (req, res) => {
  req.logout(() => res.redirect("/"));
});

// প্রোফাইল রাউট
app.get("/api/profile", async (req, res) => {
  if (!req.user) {
    return res.status(401).send("Not authenticated");
  }
  try {
    const user = await User.findById(req.user.id);
    res.json(user);
  } catch (err) {
    res.status(500).send("Error fetching user profile");
  }
});

app.listen(5000, () => {
  console.log("Server started on http://localhost:5000");
});
