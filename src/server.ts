import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pkg from "pg";




// 1. Tell TypeScript about your session data
declare module "express-session" {
    interface SessionData {
        userId: number;
    }
}

dotenv.config();

const { Pool } = pkg;

export const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: parseInt(process.env.DB_PORT || "0") || 0,
});

const app = express();

app.use(bodyParser.json());
app.use(cors({
    origin: process.env.FRONTEND_URL, // your frontend
    credentials: true
}));

app.use(session({
    name: process.env.SESSION_NAME,
    secret: process.env.SESSION_SECRET || "",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.COOKIE_SECURE === "true", // set true in production with HTTPS
        sameSite: "lax",
        maxAge: parseInt(process.env.SESSION_MAX_AGE || "0")
    }
}));

interface User {
    id: number;
    email: string;
    password: string;
    username: string;
}

// const users: User[] = [];

// For testing, create one user with hashed password
// const createTestUser = async () => {
//     const email = process.env.TEST_EMAIL || "";
//     const password = process.env.TEST_PASSWORD || "";
//     const username = process.env.TEST_USERNAME || "";
//     const saltRounds = parseInt(process.env.SALT_ROUNDS || "0");

//     const hash = await bcrypt.hash(password, saltRounds);
//     users.push({ id: 1, email, password: hash, username });
// };
// createTestUser();


app.post("/login", async (req, res) => {

    if (req.session.userId) {
        return res.status(400).send("You are already logged in.");
    }

    const { email, password } = req.body;

    try {
        // 1️⃣ Find user in DB
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const user: User = result.rows[0];

        // 2️⃣ Compare password
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // 3️⃣ Create session
        req.session.userId = user.id;

        // 4️⃣ Send response
        res.json({
            message: "Logged in successfully",
            user: {
                id: user.id,
                email: user.email,
                username: user.username
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
    }
});


const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    if (!req.session.userId) return res.status(401).send("Unauthorized");
    next();
};

app.get("/dashboard", authMiddleware, (req, res) => {
    res.send(`Welcome user ${req.session.userId}`);
});

app.post("/signup", async (req, res) => {
    const { email, password, username } = req.body;
    const saltRounds = parseInt(process.env.SALT_ROUNDS || "0") || 0;

    ////////////////////////db
    try {
        // hash password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // basic validation
        if (!email || !password || !username) return res.status(400).send("Email, password and username required");
        if (email === "" || password === "" || username === "") return res.status(400).send("Email, password and username required");


        /////////////////db stuff
        const result = await pool.query(
            "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING id",
            [email, hashedPassword, username]
        );

        req.session.userId = result.rows[0].id;
        res.send("User registered and logged in!");
    } catch (err: any) {
        console.error(err);

        if (err.code === "23505") {
            return res.status(400).json({ error: "Email already exists" });
        }

        res.status(500).json({ error: "Signup failed" });
    }
    ////////////////////////db







    // // check if user already exists
    // const existingUser = users.find(u => u.email === email);
    // if (existingUser) return res.status(400).send("User already exists");

    // // create new user
    // const newUser = { id: users.length + 1, email, password: hashedPassword, username };
    // users.push(newUser);

    // // automatically log them in by creating session
    // req.session.userId = newUser.id;

    // res.send("User registered and logged in!");
});

app.get("/me", authMiddleware, async (req, res) => {

    const result = await pool.query(
        "SELECT id, email, username FROM users WHERE id = $1",
        [req.session.userId]
    );

    if (result.rows.length === 0) {
        return res.status(401).send("Unauthorized");
    }

    res.json({
        authenticated: true,
        user: result.rows[0]
    });
});



app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send("Logout failed");
        res.clearCookie(process.env.SESSION_NAME || "0");
        res.send("Logged out");
    });
});

app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));
