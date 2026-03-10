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

// =========== REST API: Search & Friends ===========

// GET /api/search?q=keyword  (search registered users)
app.get('/api/search', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const q = (req.query.q || '').trim();
  if (q.length < 1) return res.json([]);
  const users = await db.searchUsers(q, session.Username);
  // Attach friendship status for each result
  const results = [];
  for (const u of users) {
    const status = await db.getFriendshipStatus(session.Username, u.Username);
    results.push({ username: u.Username, friendshipStatus: status });
  }
  res.json(results);
});

// GET /api/friends
app.get('/api/friends', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const friends = await db.getFriends(session.Username);
  // For each friend, check if online
  const result = friends.map((f) => {
    const onlineEntry = [...connectedUsers.entries()].find(([, v]) => v.username === f.FriendUsername);
    return {
      username: f.FriendUsername,
      online: !!onlineEntry,
      socketId: onlineEntry ? onlineEntry[0] : null,
      publicKey: onlineEntry ? onlineEntry[1].publicKey : null,
    };
  });
  res.json(result);
});

// GET /api/user-status/:username  (get any user's online status for direct chat)
app.get('/api/user-status/:username', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const target = req.params.username;
  const user = await db.getUserByUsername(target);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const onlineEntry = [...connectedUsers.entries()].find(([, v]) => v.username === target);
  res.json({
    username: target,
    online: !!onlineEntry,
    socketId: onlineEntry ? onlineEntry[0] : null,
    publicKey: onlineEntry ? onlineEntry[1].publicKey : null,
  });
});

// POST /api/friend-request  { toUsername }
app.post('/api/friend-request', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const { toUsername } = req.body;
  if (!toUsername) return res.status(400).json({ error: 'toUsername required' });
  if (toUsername === session.Username) return res.status(400).json({ error: 'Cannot add yourself' });
  const targetUser = await db.getUserByUsername(toUsername);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  const result = await db.sendFriendRequest(session.Username, toUsername);
  if (result.error) return res.status(409).json(result);

  // Notify the target user via socket if online
  const targetSocket = [...connectedUsers.entries()].find(([, v]) => v.username === toUsername);
  if (targetSocket) {
    io.to(targetSocket[0]).emit('friend-request-received', { from: session.Username });
  }
  // If auto-accepted, notify both
  if (result.status === 'accepted') {
    if (targetSocket) {
      io.to(targetSocket[0]).emit('friend-accepted', { friend: session.Username });
    }
  }
  res.json(result);
});

// GET /api/friend-requests  (pending incoming requests)
app.get('/api/friend-requests', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const requests = await db.getPendingRequests(session.Username);
  res.json(requests);
});

// POST /api/friend-request/:id/accept
app.post('/api/friend-request/:id/accept', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const result = await db.acceptFriendRequest(parseInt(req.params.id), session.Username);
  if (result.error) return res.status(400).json(result);

  // Notify the sender via socket if online
  const senderSocket = [...connectedUsers.entries()].find(([, v]) => v.username === result.friend);
  if (senderSocket) {
    io.to(senderSocket[0]).emit('friend-accepted', { friend: session.Username });
  }
  res.json(result);
});

// POST /api/friend-request/:id/reject
app.post('/api/friend-request/:id/reject', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const result = await db.rejectFriendRequest(parseInt(req.params.id), session.Username);
  res.json(result);
});

io.on('connection', (socket) => {
  console.log(`[Server] New connection: ${socket.id} (${socket.username})`);

  // Client sends its public key after connecting
  socket.on('register', ({ publicKey }) => {
    connectedUsers.set(socket.id, { username: socket.username, publicKey });
    console.log(`[Server] User online: ${socket.username} (${socket.id})`);
    // Notify friends that this user came online
    notifyFriendsOnlineStatus(socket.username);
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
      senderPublicKey: sender ? sender.publicKey : null,
    });
  });

  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      console.log(`[Server] User disconnected: ${user.username}`);
      connectedUsers.delete(socket.id);
      notifyFriendsOnlineStatus(user.username);
    } else {
      connectedUsers.delete(socket.id);
    }
  });
});

// Notify all online friends that a user's status changed
async function notifyFriendsOnlineStatus(username) {
  try {
    const friends = await db.getFriends(username);
    for (const f of friends) {
      const friendSocket = [...connectedUsers.entries()].find(([, v]) => v.username === f.FriendUsername);
      if (friendSocket) {
        io.to(friendSocket[0]).emit('friend-status-changed', { username });
      }
    }
  } catch (err) {
    console.error('[Server] Error notifying friends:', err.message);
  }
}

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
