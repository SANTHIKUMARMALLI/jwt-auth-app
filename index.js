require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');


const app = express();
app.use(express.json());


const JWT_SECRET = process.env.JWT_SECRET;
const EMAIL_FROM = 'mskumar612@gmail.com';

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'Suma@123',
  database: 'jwtdb',
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mskumar0612@gmail.com',
    pass: 'xdjn wuun aadm arpb',
  },
});

// Send email confirmation
async function sendConfirmationEmail(email, token) {
  const confirmUrl = `http://ec2-3-86-31-55.compute-1.amazonaws.com/confirm-email?token=${token}`;
  await transporter.sendMail({
    from: EMAIL_FROM,
    to: email,
    subject: 'Confirm your email',
    text: `Click to confirm: ${confirmUrl}`,
  });
}

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const conn = await pool.getConnection();
    const [existing] = await conn.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      conn.release();
      return res.status(400).json({ error: 'Email already in use' });
    }

    const emailToken = crypto.randomBytes(32).toString('hex');
    const hash = await bcrypt.hash(password, 10);

    await conn.query(
      'INSERT INTO users (username, email, password_hash, email_confirmed, email_confirm_token) VALUES (?, ?, ?, false, ?)',
      [username, email, hash, emailToken]
    );

    conn.release();
    await sendConfirmationEmail(email, emailToken);
    res.json({ message: 'Check your email to confirm registration' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Email confirmation
app.get('/confirm-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Missing token');

  try {
    const conn = await pool.getConnection();
    const [rows] = await conn.query('SELECT id FROM users WHERE email_confirm_token = ?', [token]);
    if (rows.length === 0) {
      conn.release();
      return res.status(400).send('Invalid token');
    }

    await conn.query('UPDATE users SET email_confirmed = true, email_confirm_token = NULL WHERE id = ?', [rows[0].id]);
    conn.release();

    res.send('Email confirmed! You can now log in.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

// Login route with JWT cookie
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  try {
    const conn = await pool.getConnection();
    const [users] = await conn.query('SELECT id, password_hash, email_confirmed FROM users WHERE email = ?', [email]);
    conn.release();

    if (users.length === 0) return res.status(400).json({ error: 'Invalid email or password' });

    const user = users[0];
    if (!user.email_confirmed) return res.status(403).json({ error: 'Email not confirmed' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

     res.json({ message: 'Login successful',token});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Get token from "Bearer <token>"

  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}




//Protected route
app.get('/protected-resource', authenticateToken, (req, res) => {
  res.json({ message: 'You have access', userId: req.user.userId });
});

// Start server
app.listen(3000, '0.0.0.0', () => {
  console.log('Server running at http://localhost:3000');
});
