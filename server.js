const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const db = require('./db');

const scrypt = promisify(crypto.scrypt);

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// connectedUsers remains in-memory (transient socket state)
const connectedUsers = new Map();

async function hashPassword(password, salt) {
  const derivedKey = await scrypt(password, salt, 64);
  return derivedKey.toString('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const trimmed = username.trim();
  if (trimmed.length < 3 || trimmed.length > 20) {
    return res.status(400).json({ error: 'Username must be 3–20 characters' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  const existing = await db.getUserByUsername(trimmed);
  if (existing) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = await hashPassword(password, salt);
  await db.createUser(trimmed, passwordHash, salt);
  console.log(`[Server] New user registered: ${trimmed}`);
  const token = generateToken();
  await db.createSession(token, trimmed);
  res.json({ token, username: trimmed });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const user = await db.getUserByUsername(username.trim());
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const hash = await hashPassword(password, user.Salt);
  const hashBuf = Buffer.from(hash, 'hex');
  const storedBuf = Buffer.from(user.PasswordHash, 'hex');
  if (!crypto.timingSafeEqual(hashBuf, storedBuf)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  console.log(`[Server] User logged in: ${user.Username}`);
  const token = generateToken();
  await db.createSession(token, user.Username);
  res.json({ token, username: user.Username });
});

// Socket.io authentication middleware
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication required'));
  const session = await db.getSessionByToken(token);
  if (session) {
    socket.username = session.Username;
    next();
  } else {
    next(new Error('Authentication required'));
  }
});

io.on('connection', (socket) => {
  console.log(`[Server] New connection: ${socket.id} (${socket.username})`);

  // Client sends its public key after connecting
  socket.on('register', ({ publicKey }) => {
    connectedUsers.set(socket.id, { username: socket.username, publicKey });
    console.log(`[Server] User online: ${socket.username} (${socket.id})`);
    broadcastUserList();
  });

  // Relay encrypted private message from sender to recipient
  socket.on('private-message', (data) => {
    const sender = connectedUsers.get(socket.id);
    const senderName = sender ? sender.username : 'Unknown';
    const recipient = connectedUsers.get(data.to);
    const recipientName = recipient ? recipient.username : null;
    console.log(`[Server] Relaying encrypted message from ${senderName} to ${data.to}`);
    console.log('[Server] *** Server CANNOT read the message content (E2E encrypted) ***');

    // Save encrypted message to database
    if (recipientName) {
      db.saveMessage(senderName, recipientName, data.encryptedMessage, data.signature).catch((err) =>
        console.error('[DB] Error saving message:', err.message)
      );
    }

    io.to(data.to).emit('private-message', {
      from: socket.id,
      fromUsername: senderName,
      encryptedMessage: data.encryptedMessage,
      signature: data.signature,
    });
  });

  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      console.log(`[Server] User disconnected: ${user.username}`);
    }
    connectedUsers.delete(socket.id);
    broadcastUserList();
  });
});

function broadcastUserList() {
  const userList = [];
  for (const [id, { username, publicKey }] of connectedUsers) {
    userList.push({ id, username, publicKey });
  }
  io.emit('user-list', userList);
}

const PORT = process.env.PORT || 3000;

// Connect to database before starting server
db.getPool()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`[Server] SecChatApp running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('[DB] Failed to connect to SQL Server:', err.message);
    console.error('[DB] Make sure SQL Server is running and Named Pipes protocol is enabled.');
    process.exit(1);
  });

module.exports = { app, server, io };
