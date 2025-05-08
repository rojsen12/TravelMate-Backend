const result = require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());


const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  console.log('Dane logowania:', { email, password });
  
  try {
    const userCheck = await pool.query(
      'SELECT * FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );
    
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Użytkownik o podanym emailu lub nazwie już istnieje' });
    }
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hashedPassword]
    );
    
    const token = jwt.sign(
      { id: result.rows[0].id, username: result.rows[0].username },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.status(201).json({
      message: 'Użytkownik zarejestrowany pomyślnie',
      user: {
        id: result.rows[0].id,
        username: result.rows[0].username,
        email: result.rows[0].email
      },
      token
    });
  } catch (error) {
    console.error('Błąd rejestracji:', error);
    res.status(500).json({ error: 'Wystąpił błąd podczas rejestracji' });
  }
});

// Endpoint logowania
app.post('/login', async (req, res) => {
    const { login, password } = req.body;
  
    try {
      const result = await pool.query(
        'SELECT * FROM users WHERE email = $1 OR username = $1',
        [login]
      );
  
      if (result.rows.length === 0) {
        return res.status(401).json({ error: 'Nieprawidłowy email lub hasło' });
      }
  
      const user = result.rows[0];
  
      const isValidPassword = await bcrypt.compare(password, user.password);
  
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Nieprawidłowy email lub hasło' });
      }
  
      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );
  
      res.json({
        message: 'Zalogowano pomyślnie',
        user: {
          id: user.id,
          username: user.username,
          email: user.email
        },
        token
      });
    } catch (error) {
      console.error('Błąd logowania:', error);
      res.status(500).json({ error: 'Wystąpił błąd podczas logowania' });
    }
  });
  

app.listen(port, () => {
  console.log(`Serwer działa na porcie ${port}`);
});