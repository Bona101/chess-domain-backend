import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";

import bcrypt from "bcrypt";


dotenv.config();

const app = express();

app.use(bodyParser.json());
app.use(cors({
  origin: process.env.FRONTEND_URL, // your frontend
  credentials: true
}));

app.use(session({
  name: process.env.SESSION_NAME,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true", // set true in production with HTTPS
    sameSite: "lax",
    maxAge: parseInt(process.env.SESSION_MAX_AGE) // 30 minutes
  }
}));



const users = [];

// For testing, create one user with hashed password
const createTestUser = async () => {
    const email = process.env.TEST_EMAIL || "";
    const password = process.env.TEST_PASSWORD || "";
    const saltRounds = parseInt(process.env.SALT_ROUNDS) || 0;

  const hash = await bcrypt.hash(password, saltRounds);
  users.push({ id: 1, email, password: hash });
};
createTestUser();


app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).send("Invalid credentials");

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).send("Invalid credentials");

  req.session.userId = user.id;
  res.send("Logged in");
});


const authMiddleware = (req, res, next) => {
  if (!req.session.userId) return res.status(401).send("Unauthorized");
  next();
};

app.get("/dashboard", authMiddleware, (req, res) => {
  res.send(`Welcome user ${req.session.userId}`);
});

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const saltRounds = parseInt(process.env.SALT_ROUNDS) || 0;

  // basic validation
  if (!email || !password) return res.status(400).send("Email and password required");

  // check if user already exists
  const existingUser = users.find(u => u.email === email);
  if (existingUser) return res.status(400).send("User already exists");

  // hash password
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // create new user
  const newUser = { id: users.length + 1, email, password: hashedPassword };
  users.push(newUser);

  // automatically log them in by creating session
  req.session.userId = newUser.id;

  res.send("User registered and logged in!");
});

app.get("/me", authMiddleware, (req, res) => {
  res.json({
    authenticated: true,
    userId: req.session.userId
  });
});


app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send("Logout failed");
    res.clearCookie(process.env.SESSION_NAME);
    res.send("Logged out");
  });
});

app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));
