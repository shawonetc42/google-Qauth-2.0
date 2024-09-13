// send messege and recived massege
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const cors = require("cors");

// Initialize the Express app
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:3000", // Allow requests from this origin
    credentials: true, // Allow cookies to be sent with requests
  })
);

// MongoDB Connection
const MONGO_URI =
  "mongodb+srv://shawondata:shawondata@cluster0.sigdzxx.mongodb.net/shawon?retryWrites=true&w=majority";
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

const Message = require("./models/sendMessege");

const User = mongoose.model("userss", UserSchema);

// Registration Route
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if the user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: "User already exists" });
    }

    // Create a new user
    user = new User({
      name,
      email,
      password,
    });

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Save the user
    await user.save();

    // Create and send JWT token in a cookie
    const payload = { user: { id: user.id } };

    jwt.sign(payload, "yourSecretKey", { expiresIn: "12h" }, (err, token) => {
      if (err) throw err;
      res
        .cookie("token", token, { httpOnly: true, secure: true })
        .json({ token });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Login Route
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    // JWT payload
    const payload = {
      user: {
        id: user.id,
      },
    };

    // Sign and set JWT in an HTTP-only cookie
    jwt.sign(
      payload,
      "yourSecretKey", // Replace with your secret key
      { expiresIn: 360000 },
      (err, token) => {
        if (err) throw err;
        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production", // Use secure cookies in production
          maxAge: 360000 * 1000, // Cookie expiration time
        });
        res.json({ success: true });
      }
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Profile Route (Requires Auth)
app.get("/auth/profile", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ msg: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, "yourSecretKey");
    const user = await User.findById(decoded.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Logout Route
app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("token").json({ msg: "Logged out successfully" });
});

// send messages
app.post("/api/messages", async (req, res) => {
  try {
    const { sender, receiver, message } = req.body;
    const newMessage = new Message({
      sender,
      receiver,
      message,
    });
    await newMessage.save();
    res.json(newMessage);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// get messages
app.get("/api/messages", async (req, res) => {
  try {
    const messages = await Message.find();
    res.json(messages);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
