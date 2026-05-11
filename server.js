const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const socketio = require('socket.io');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: { origin: "*" },
  transports: ['websocket', 'polling']
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ============ SQLITE DATABASE (No external service!) ============
const db = new sqlite3.Database('./messaging.db');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    uniqueId TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Messages table
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fromId TEXT NOT NULL,
    toId TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(fromId) REFERENCES users(uniqueId),
    FOREIGN KEY(toId) REFERENCES users(uniqueId)
  )`);
  
  console.log('✅ SQLite database ready (messaging.db)');
});

// Helper functions
function generateUniqueId() {
  return Math.floor(10000 + Math.random() * 90000).toString();
}

async function isUniqueId(id) {
  return new Promise((resolve, reject) => {
    db.get('SELECT uniqueId FROM users WHERE uniqueId = ?', [id], (err, row) => {
      if (err) reject(err);
      resolve(!row);
    });
  });
}

async function generateUniqueFiveDigitId() {
  let id, unique;
  do {
    id = generateUniqueId();
    unique = await isUniqueId(id);
  } while (!unique);
  return id;
}

// ============ API ROUTES ============

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) {
      return res.status(400).json({ error: 'Name and password required' });
    }
    
    const uniqueId = await generateUniqueFiveDigitId();
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run('INSERT INTO users (uniqueId, name, password) VALUES (?, ?, ?)',
      [uniqueId, name, hashedPassword],
      function(err) {
        if (err) {
          res.status(500).json({ error: err.message });
        } else {
          res.json({ success: true, uniqueId });
        }
      });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { uniqueId, password } = req.body;
  
  db.get('SELECT * FROM users WHERE uniqueId = ?', [uniqueId], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Wrong password' });
    }
    
    const token = jwt.sign({ uniqueId, name: user.name }, process.env.JWT_SECRET || 'secret123');
    res.json({ success: true, token, uniqueId, name: user.name });
  });
});

// Get all users (except current)
app.get('/api/all-users', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    db.all('SELECT uniqueId, name FROM users WHERE uniqueId != ?', [decoded.uniqueId], (err, users) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(users);
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Get messages between two users
app.post('/api/messages', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const { fromId, toId } = req.body;
    
    db.all(
      `SELECT * FROM messages 
       WHERE (fromId = ? AND toId = ?) OR (fromId = ? AND toId = ?) 
       ORDER BY timestamp ASC`,
      [fromId, toId, toId, fromId],
      (err, messages) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(messages);
      });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Save message
app.post('/api/save-message', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    const { toId, message } = req.body;
    
    db.run('INSERT INTO messages (fromId, toId, message) VALUES (?, ?, ?)',
      [decoded.uniqueId, toId, message],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
      });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ============ SOCKET.IO ============
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    socket.user = decoded;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log(`✅ User connected: ${socket.user?.name}`);
  onlineUsers.set(socket.user?.uniqueId, socket.id);

  socket.on('send-message', async (data) => {
    const { toId, message } = data;
    const fromId = socket.user.uniqueId;
    
    // Save to SQLite
    db.run('INSERT INTO messages (fromId, toId, message) VALUES (?, ?, ?)',
      [fromId, toId, message]);
    
    // Send if online
    const recipientSocketId = onlineUsers.get(toId);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('receive-message', {
        fromId,
        message,
        timestamp: new Date()
      });
    }
  });

  socket.on('disconnect', () => {
    onlineUsers.delete(socket.user?.uniqueId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
