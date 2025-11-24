import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import pool from "./db";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import type {
  User,
  UserWithPassword,
  RegisterRequest,
  LoginRequest
} from "../../shared/types/shared";

const app = express();
const port = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

const JWT_SECRET = "YOUR_SECRET_KEY_CHANGE_THIS";

// ---------------------- TOKEN BLACKLIST ----------------------
const blacklistedTokens: Set<string> = new Set();

// ---------------------- JWT TOKEN HELPERS ----------------------
const generateAccessToken = (user: any) => {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
};

const generateRefreshToken = (user: any) => {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
};

// ---------------------- JWT Middleware ----------------------
const authMiddleware = (req: any, res: Response, next: NextFunction) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied, no token provided" });
  }

  if (blacklistedTokens.has(token)) {
    return res.status(401).json({ error: "Token expired or logged out" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    req.token = token;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

// ---------------------- INIT DB ----------------------
app.get("/init-db", async (req: Request, res: Response) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({ message: "Database initialized!" });
  } catch (err) {
    res.status(500).send("Database initialization failed");
  }
});

// ---------------------- REGISTER ----------------------
app.post("/api/register", async (req: Request<{}, {}, RegisterRequest>, res: Response) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields are required" });

    const userExists = await pool.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [email, username]
    );

    if (userExists.rows.length > 0)
      return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, created_at",
      [username, email, hashedPassword]
    );

    res.status(201).json({
      message: "User registered successfully!",
      user: result.rows[0]
    });
  } catch (err) {
    res.status(500).json({ error: "Server error during registration" });
  }
});

// ---------------------- LOGIN WITH ACCESS + REFRESH TOKENS ----------------------
app.post("/api/login", async (req: Request<{}, {}, LoginRequest>, res: Response) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query<UserWithPassword>(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "Invalid email or password" });

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ error: "Invalid email or password" });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.json({
      message: "Login successful!",
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (err) {
    res.status(500).json({ error: "Server error during login" });
  }
});

// ---------------------- REFRESH TOKEN ENDPOINT ----------------------
app.post("/api/token/refresh", async (req: Request, res: Response) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "Refresh token is required" });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);

    const newAccessToken = jwt.sign(
      { id: (decoded as any).id, email: (decoded as any).email },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({
      accessToken: newAccessToken
    });
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }
});

// ---------------------- PROTECTED LOGOUT ----------------------
app.post("/api/logout", authMiddleware, (req: any, res: Response) => {
  const token = req.token;

  blacklistedTokens.add(token);

  res.json({ message: "Logged out successfully! Token invalidated." });
});

// ---------------------- PROTECTED PROFILE ----------------------
app.get("/api/profile", authMiddleware, async (req: any, res: Response) => {
  try {
    const userId = req.user.id;

    const result = await pool.query<User>(
      "SELECT id, username, email, created_at FROM users WHERE id = $1",
      [userId]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------- PROTECTED ALL USERS ----------------------
app.get("/api/allusers", authMiddleware, async (req: Request, res: Response) => {
  try {
    const result = await pool.query<User>(
      "SELECT id, username, email, created_at FROM users ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------- PROTECTED GET USER BY ID ----------------------
app.get("/api/user/:id", authMiddleware, async (req: any, res: Response) => {
  try {
    const userId = parseInt(req.params.id, 10);

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const result = await pool.query<User>(
      "SELECT id, username, email, created_at FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------- TEST ----------------------
app.get("/", (req: Request, res: Response) => {
  res.send("Hello from JWT Protected PERN API!");
});

// ---------------------- SERVER ----------------------
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
