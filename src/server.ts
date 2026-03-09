import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import bodyParser from "body-parser";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pkg from "pg";
import { OAuth2Client } from 'google-auth-library';
import crypto from "crypto";


// 1. Tell TypeScript about your session data
declare module "express-session" {
    interface SessionData {
        userId: number;
    }
}

dotenv.config();

function generateRandomUsername(length: number = 6): string {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

async function getGoogleUser(code: string) {
    // Exchange the 'code' for tokens
    const { tokens } = await client.getToken(code);

    // Verify the ID token to get user profile data
    const ticket = await client.verifyIdToken({
        idToken: tokens.id_token ?? "",
        audience: process.env.CLIENT_ID,
    });

    return ticket.getPayload(); // Returns { email, name, picture, etc. }
}

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
    origin: process.env.FRONTEND_URL,
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

app.post("/auth/google", async (req, res) => {
    const { token } = req.body;

    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();

        // MANDATORY SECURITY CHECK
        if (!payload?.email_verified) {
            return res.status(401).json({ error: "Email not verified" });
        }

        // DB Logic: Find or Create User
        let { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [payload.email]);
        let user = rows[0];

        if (!user) {
            const newUser = await pool.query(
                "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING id",
                [payload.email, "OAUTH_USER", generateRandomUsername()]
            );
            user = newUser.rows[0];
        }

        // Start Session
        req.session.userId = user.id;
         res.json({
            message: "Logged in successfully",
            user: {
                id: user.id,
                email: user.email,
                username: user.username
            }
        });

    } catch (err) {
        res.status(401).json({ error: "Invalid Token" });
    }
});

// app.get('/api/auth/google/callback', async (req, res) => {
//     const { code } = req.query; // Step 1

//     // we will only use code if it is a string
//     if (typeof code !== 'string') {
//         return res.status(400).send("Invalid Google code");
//     }

//     // Step 2 & 3: Exchange code for user details (using a library like 'google-auth-library')
//     const googleUser = await getGoogleUser(code);

//     if (!googleUser) {
//         return res.status(400).send("Missing user's info");
//     }

//     if (!googleUser.email_verified) {
//         return res.status(401).send("Google email not verified.");
//     }

//     // Step 4: Logic
//     try {
//         // 1️⃣ Find user in DB
//         const result = await pool.query(
//             "SELECT * FROM users WHERE email = $1",
//             [googleUser.email]
//         );

//         if (result.rows.length === 0) {
//             try {
//                 const newUser = await pool.query(
//                     "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING id",
//                     [googleUser.email, "OAUTH_USER", generateRandomUsername()]
//                 );
//                 req.session.userId = newUser.rows[0].id;
//                 return res.json({
//                     message: "User registered and logged in!",
//                     user: {
//                         id: newUser.rows[0].id,
//                         email: newUser.rows[0].email,
//                         username: newUser.rows[0].username
//                     }
//                 });
//             } catch (err: any) {
//                 console.error(err);

//                 if (err.code === "23505") {
//                     return res.status(400).json({ error: "Email already exists" });
//                 }

//                 return res.status(500).json({ error: "Signup failed" });
//             }
//         }

//         const userId = result.rows[0].id;

//         req.session.userId = userId;

//         return res.json({
//             message: "Logged in successfully",
//             user: {
//                 id: result.rows[0].id,
//                 email: result.rows[0].email,
//                 username: result.rows[0].username
//             }
//         });
//     } catch (err: any) {
//         console.error(err);
//         return res.status(500).json({ message: "Server error" });
//     }
// });


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

    try {
        // hash password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // basic validation
        if (!email || !password || !username) return res.status(400).send("Email, password and username required");
        if (email === "" || password === "" || username === "") return res.status(400).send("Email, password and username required");


        // db stuff
        const result = await pool.query(
            "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING id",
            [email, hashedPassword, username]
        );

        req.session.userId = result.rows[0].id;
        res.json({
            message: "User registered and logged in!",
            user: {
                id: result.rows[0].id,
                email: result.rows[0].email,
                username: result.rows[0].username
            }
        });
    } catch (err: any) {
        console.error(err);

        if (err.code === "23505") {
            return res.status(400).json({ error: "Email already exists" });
        }

        res.status(500).json({ error: "Signup failed" });
    }
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
