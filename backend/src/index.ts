import express, { Request, Response } from 'express';
import cors from 'cors';
import pool from './db';
import type { 
  User, 
  UserWithPassword, 
  RegisterRequest, 
  LoginRequest, 
  AuthResponse 
} from '../../shared/types/shared';
const app = express();
const port = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

// Database Initialization
app.get('/init-db', async (req: Request, res: Response) => {
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
    res.json({ message: 'Database tables created successfully!' });
  } catch (err) {
    console.error('Database initialization error:', err);
    res.status(500).send('Database initialization failed');
  }
});

// Register Route
app.post('/api/register', async (req: Request<{}, {}, RegisterRequest>, res: Response<AuthResponse | { error: string }>) => {
  try {
    const { username, email, password }: RegisterRequest = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'Username, email and password are required' 
      });
    }

    // Check if user exists
    const userExists = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({ 
        error: 'User already exists with this email or username' 
      });
    }

    // Create user
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, email, password]
    );

    const newUser: User = result.rows[0];
    
    const response: AuthResponse = {
      message: 'User registered successfully!',
      user: newUser
    };

    res.status(201).json(response);

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login Route - FIXED VERSION
app.post('/api/login', async (req: Request<{}, {}, LoginRequest>, res: Response<AuthResponse | { error: string }>) => {
  try {
    const { email, password }: LoginRequest = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }

    // Use UserWithPassword type for database result
    const result = await pool.query<UserWithPassword>(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ 
        error: 'Invalid email or password' 
      });
    }

    const user: UserWithPassword = result.rows[0];
    const isValidPassword = password === user.password;

    if (!isValidPassword) {
      return res.status(400).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Create response without password
    const userResponse: User = {
      id: user.id,
      username: user.username,
      email: user.email,
      created_at: user.created_at
    };

    const response: AuthResponse = {
      message: 'Login successful!',
      user: userResponse
    };

    res.json(response);

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get all users
app.get('/api/users', async (req: Request, res: Response<User[] | { error: string }>) => {
  try {
    const result = await pool.query<User>(
      'SELECT id, username, email, created_at FROM users ORDER BY created_at DESC'
    );
    const users: User[] = result.rows;
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Existing routes
app.get('/', (req: Request, res: Response) => {
  res.send('Hello from PERN Stack Backend!');
});

app.get('/db-test', async (req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});