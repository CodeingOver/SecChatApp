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

// =========== HTTP Security Headers ===========
app.use((req, res, next) => {
  // Chống Clickjacking: không cho phép nhúng trang trong iframe
  res.setHeader('X-Frame-Options', 'DENY');
  // Chống MIME-type sniffing: ngăn trình duyệt đoán Content-Type
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Tắt Referrer khi chuyển trang giảm lộ thông tin
  res.setHeader('Referrer-Policy', 'no-referrer');
  // Chặn quyền camera, microphone, geolocation...
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // Cache-Control: không cache dữ liệu nhạy cảm
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// =========== Input Sanitization Utility ===========
// Loại bỏ tất cả HTML tags để chống XSS (defense-in-depth)
function sanitizeHtml(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>"'&]/g, (ch) => {
    switch (ch) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#39;';
      case '&': return '&amp;';
      default: return ch;
    }
  });
}

// Kiểm tra định dạng username: chỉ cho phép chữ cái, số, gạch dưới
function isValidUsername(username) {
  return /^[a-zA-Z0-9_]+$/.test(username);
}

// =========== Rate Limiting ===========
// Giới hạn số lần gọi API theo IP để chống brute-force
const rateLimitStore = new Map();

function rateLimit(windowMs, maxRequests) {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const key = `${req.route ? req.route.path : req.path}:${ip}`;
    const record = rateLimitStore.get(key);
    if (!record || now - record.windowStart > windowMs) {
      rateLimitStore.set(key, { windowStart: now, count: 1 });
      return next();
    }
    record.count++;
    if (record.count > maxRequests) {
      console.warn(`[Security] Rate limit exceeded for ${key}`);
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    next();
  };
}

// Dọn dẹp rateLimitStore định kỳ (mỗi 5 phút)
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimitStore) {
    if (now - record.windowStart > 300000) rateLimitStore.delete(key);
  }
}, 300000);

// =========== Source Protection: XOR encrypt/decrypt helper ===========
const API_CIPHER_KEY = crypto.randomBytes(32).toString('hex');  // per-process key

function xorCipher(text, key) {
  const keyBytes = Buffer.from(key, 'utf8');
  const textBytes = Buffer.from(text, 'utf8');
  const out = Buffer.alloc(textBytes.length);
  for (let i = 0; i < textBytes.length; i++) {
    out[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return out.toString('base64');
}

function xorDecipher(b64, key) {
  const keyBytes = Buffer.from(key, 'utf8');
  const data = Buffer.from(b64, 'base64');
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ keyBytes[i % keyBytes.length];
  }
  return out.toString('utf8');
}

// =========== Block direct access to JS source files ===========
const PROTECTED_SCRIPTS = ['app.js', 'crypto.js', 'devtools-guard.js'];

app.use((req, res, next) => {
  const filename = path.basename(req.path);
  if (PROTECTED_SCRIPTS.includes(filename) && req.path.startsWith('/')) {
    // Allow only the /api/load-scripts endpoint to serve scripts
    return res.status(403).send('// Access Denied');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// =========== Serve scripts via encrypted endpoint ===========
app.get('/api/load-scripts', (req, res) => {
  const nonce = req.query.nonce;
  if (!nonce) return res.status(400).json({ error: 'nonce required' });
  try {
    const scripts = PROTECTED_SCRIPTS.map(name => {
      const filePath = path.join(__dirname, 'public', name);
      const content = require('fs').readFileSync(filePath, 'utf8');
      return { name, content: xorCipher(content, nonce) };
    });
    res.json({ scripts, key: nonce });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load scripts' });
  }
});

// =========== API Response Encryption Middleware ===========
// Wraps all /api/* JSON responses in { _enc: <xor-encrypted-base64> }
// so Network tab shows encrypted data instead of readable JSON.
app.use('/api', (req, res, next) => {
  // Skip the load-scripts and cipher-key endpoints
  if (req.path === '/load-scripts' || req.path === '/cipher-key') return next();

  // Local debug mode for tools like Thunder Client:
  // send header `x-debug-plain: 1` to receive plaintext JSON.
  const isLocalIp = req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1';
  const wantsPlain = req.headers['x-debug-plain'] === '1';
  if (process.env.NODE_ENV !== 'production' && isLocalIp && wantsPlain) return next();

  const originalJson = res.json.bind(res);
  res.json = (data) => {
    const plain = JSON.stringify(data);
    const encrypted = xorCipher(plain, API_CIPHER_KEY);
    originalJson({ _enc: encrypted });
  };
  next();
});

// =========== API Request Decryption Middleware ===========
// If request body contains { _enc: "..." }, decrypt it before processing.
app.use('/api', (req, res, next) => {
  if (req.body && req.body._enc && typeof req.body._enc === 'string') {
    try {
      const decrypted = xorDecipher(req.body._enc, API_CIPHER_KEY);
      req.body = JSON.parse(decrypted);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid encrypted payload' });
    }
  }
  next();
});

// Expose the cipher key via a special endpoint (fetched once by the client)
app.get('/api/cipher-key', (req, res) => {
  // Return the key directly (transmitted once, then used for all calls)
  // In production, this would use a key exchange protocol (e.g., Diffie-Hellman)
  res.send(API_CIPHER_KEY);
});

// connectedUsers remains in-memory (transient socket state)
const connectedUsers = new Map();

async function hashPassword(password, salt) {
  const derivedKey = await scrypt(password, salt, 64);
  return derivedKey.toString('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// GET /api/me  (verify stored session token – used for auto-login after F5)
app.get('/api/me', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  res.json({ username: session.Username });
});

// POST /api/register
app.post('/api/register', rateLimit(60000, 5), async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const trimmed = username.trim();
  if (trimmed.length < 3 || trimmed.length > 20) {
    return res.status(400).json({ error: 'Username must be 3–20 characters' });
  }
  if (!isValidUsername(trimmed)) {
    return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
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
app.post('/api/login', rateLimit(60000, 10), async (req, res) => {
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

// GET /api/conversations  (all users you've chatted with, including strangers)
app.get('/api/conversations', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const partners = await db.getConversationPartners(session.Username);
  const result = [];
  for (const partnerUsername of partners) {
    const onlineEntry = [...connectedUsers.entries()].find(([, v]) => v.username === partnerUsername);
    let publicKey = onlineEntry ? onlineEntry[1].publicKey : null;
    if (!publicKey) publicKey = await db.getUserPublicKey(partnerUsername);
    const friendshipStatus = await db.getFriendshipStatus(session.Username, partnerUsername);
    result.push({
      username: partnerUsername,
      online: !!onlineEntry,
      socketId: onlineEntry ? onlineEntry[0] : null,
      publicKey,
      friendshipStatus,
    });
  }
  res.json(result);
});

// GET /api/search?q=keyword  (search registered users)
app.get('/api/search', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const q = sanitizeHtml((req.query.q || '').trim());
  if (q.length < 1) return res.json([]);
  if (q.length > 50) return res.json([]);  // Giới hạn độ dài truy vấn tìm kiếm
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
  // For each friend, check if online; if offline, use stored public key
  const result = [];
  for (const f of friends) {
    const onlineEntry = [...connectedUsers.entries()].find(([, v]) => v.username === f.FriendUsername);
    let publicKey = onlineEntry ? onlineEntry[1].publicKey : null;
    if (!publicKey) {
      publicKey = await db.getUserPublicKey(f.FriendUsername);
    }
    result.push({
      username: f.FriendUsername,
      online: !!onlineEntry,
      socketId: onlineEntry ? onlineEntry[0] : null,
      publicKey,
    });
  }
  res.json(result);
});

// POST /api/update-public-key  (save public key to DB for offline messaging)
app.post('/api/update-public-key', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error: 'publicKey required' });
  await db.updatePublicKey(session.Username, publicKey);
  res.json({ status: 'ok' });
});

// POST /api/backup-keys  (save encrypted private keys to server for cross-browser sync)
app.post('/api/backup-keys', rateLimit(60000, 5), async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const { encryptedKeys } = req.body;
  if (!encryptedKeys || typeof encryptedKeys !== 'string') return res.status(400).json({ error: 'encryptedKeys required' });
  if (encryptedKeys.length > 100000) return res.status(400).json({ error: 'Payload too large' });
  await db.saveEncryptedKeys(session.Username, encryptedKeys);
  res.json({ status: 'ok' });
});

// GET /api/backup-keys  (retrieve encrypted private keys for cross-browser restore)
app.get('/api/backup-keys', rateLimit(60000, 10), async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const encryptedKeys = await db.getEncryptedKeys(session.Username);
  if (!encryptedKeys) return res.status(404).json({ error: 'No backup found' });
  res.json({ encryptedKeys });
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
  let publicKey = onlineEntry ? onlineEntry[1].publicKey : null;
  if (!publicKey) {
    publicKey = user.PublicKey || null;
  }
  res.json({
    username: target,
    online: !!onlineEntry,
    socketId: onlineEntry ? onlineEntry[0] : null,
    publicKey,
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

// POST /api/send-message  (send message to offline users via REST)
app.post('/api/send-message', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const { toUsername, encryptedMessage, encryptedForSender, signature } = req.body;
  if (!toUsername || !encryptedMessage) return res.status(400).json({ error: 'Missing fields' });
  // Giới hạn kích thước tin nhắn mã hóa (tối đa 50KB)
  if (encryptedMessage.length > 51200) return res.status(400).json({ error: 'Message too large' });
  const targetUser = await db.getUserByUsername(toUsername);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  await db.saveMessage(session.Username, toUsername, encryptedMessage, encryptedForSender || null, signature || null);
  res.json({ status: 'saved' });
});

// GET /api/messages/:username  (load chat history with a user)
app.get('/api/messages/:username', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const targetUsername = req.params.username;
  const messages = await db.getMessages(session.Username, targetUsername);
  res.json(messages);
});

// GET /api/public-key/:username  (get stored public key for offline users)
app.get('/api/public-key/:username', async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Auth required' });
  const session = await db.getSessionByToken(token);
  if (!session) return res.status(401).json({ error: 'Invalid token' });
  const publicKey = await db.getUserPublicKey(req.params.username);
  if (!publicKey) return res.status(404).json({ error: 'Public key not found' });
  res.json({ publicKey });
});

io.on('connection', (socket) => {
  console.log(`[Server] New connection: ${socket.id} (${socket.username})`);

  // Client sends its public key after connecting
  socket.on('register', ({ publicKey }) => {
    connectedUsers.set(socket.id, { username: socket.username, publicKey });
    console.log(`[Server] User online: ${socket.username} (${socket.id})`);
    // Save public key to database for offline messaging
    db.updatePublicKey(socket.username, publicKey).catch((err) =>
      console.error('[DB] Error saving public key:', err.message)
    );
    // Notify friends that this user came online
    notifyFriendsOnlineStatus(socket.username);
  });

  // Relay encrypted private message from sender to recipient
  socket.on('private-message', (data) => {
    const sender = connectedUsers.get(socket.id);
    const senderName = sender ? sender.username : 'Unknown';
    const recipient = connectedUsers.get(data.to);
    const recipientName = recipient ? recipient.username : null;
    console.log(`[Server] Relaying encrypted message from ${senderName} to ${recipientName || data.to}`);
    console.log('[Server] *** Server CANNOT read the message content (E2E encrypted) ***');

    // Save encrypted message to database (use toUsername if recipient offline)
    const targetName = recipientName || data.toUsername;
    if (targetName) {
      db.saveMessage(senderName, targetName, data.encryptedMessage, data.encryptedForSender || null, data.signature).catch((err) =>
        console.error('[DB] Error saving message:', err.message)
      );
    }

    if (recipient) {
      io.to(data.to).emit('private-message', {
        from: socket.id,
        fromUsername: senderName,
        encryptedMessage: data.encryptedMessage,
        signature: data.signature,
        senderPublicKey: sender ? sender.publicKey : null,
      });
    }
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
  .then(async (pool) => {
    // Auto-migrate: add missing columns if they don't exist yet
    await pool.request().query(
      "IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Users') AND name = 'EncryptedKeys') ALTER TABLE Users ADD EncryptedKeys NVARCHAR(MAX) NULL"
    );
    await pool.request().query(
      "IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('Messages') AND name = 'EncryptedForSender') ALTER TABLE Messages ADD EncryptedForSender NVARCHAR(MAX) NULL"
    );
    console.log('[DB] Schema migration complete');
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
