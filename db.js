const sql = require('mssql/msnodesqlv8');

// ============================================
// Ket noi SQL Server bang Named Pipes
// ============================================
// Doi "SQLEXPRESS" thanh ten instance cua ban neu khac
// Neu dung default instance, doi server thanh: 'np:\\\\.\\pipe\\sql\\query'
const config = {
  connectionString:
    'Driver={ODBC Driver 17 for SQL Server};Server=np:\\\\.\\pipe\\MSSQL$SQLEXPRESS\\sql\\query;Database=SecChatDB;Trusted_Connection=yes;',
};

let pool = null;

async function getPool() {
  if (pool) return pool;
  pool = await sql.connect(config);
  console.log('[DB] Connected to SQL Server via Named Pipes');
  return pool;
}

// ============================================
// User operations
// ============================================

async function createUser(username, passwordHash, salt) {
  const db = await getPool();
  await db
    .request()
    .input('username', sql.NVarChar(20), username)
    .input('passwordHash', sql.NVarChar(128), passwordHash)
    .input('salt', sql.NVarChar(32), salt)
    .query(
      'INSERT INTO Users (Username, PasswordHash, Salt) VALUES (@username, @passwordHash, @salt)'
    );
}

async function getUserByUsername(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('username', sql.NVarChar(20), username)
    .query('SELECT Username, PasswordHash, Salt, PublicKey FROM Users WHERE Username = @username');
  return result.recordset[0] || null;
}

async function updatePublicKey(username, publicKey) {
  const db = await getPool();
  await db
    .request()
    .input('username', sql.NVarChar(20), username)
    .input('publicKey', sql.NVarChar(sql.MAX), publicKey)
    .query('UPDATE Users SET PublicKey = @publicKey WHERE Username = @username');
}

async function getUserPublicKey(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('username', sql.NVarChar(20), username)
    .query('SELECT PublicKey FROM Users WHERE Username = @username');
  const row = result.recordset[0];
  return row ? row.PublicKey : null;
}

// ============================================
// Session operations
// ============================================

async function createSession(token, username) {
  const db = await getPool();
  await db
    .request()
    .input('token', sql.NVarChar(64), token)
    .input('username', sql.NVarChar(20), username)
    .query('INSERT INTO Sessions (Token, Username) VALUES (@token, @username)');
}

async function getSessionByToken(token) {
  const db = await getPool();
  const result = await db
    .request()
    .input('token', sql.NVarChar(64), token)
    .query('SELECT Username FROM Sessions WHERE Token = @token');
  return result.recordset[0] || null;
}

async function deleteSession(token) {
  const db = await getPool();
  await db
    .request()
    .input('token', sql.NVarChar(64), token)
    .query('DELETE FROM Sessions WHERE Token = @token');
}

// ============================================
// Message operations
// ============================================

async function saveMessage(fromUsername, toUsername, encryptedMessage, encryptedForSender, signature) {
  const db = await getPool();
  await db
    .request()
    .input('from', sql.NVarChar(20), fromUsername)
    .input('to', sql.NVarChar(20), toUsername)
    .input('msg', sql.NVarChar(sql.MAX), encryptedMessage)
    .input('efs', sql.NVarChar(sql.MAX), encryptedForSender || null)
    .input('sig', sql.NVarChar(sql.MAX), signature || null)
    .query(
      'INSERT INTO Messages (FromUsername, ToUsername, EncryptedMessage, EncryptedForSender, Signature) VALUES (@from, @to, @msg, @efs, @sig)'
    );
}

async function getMessages(user1, user2, limit = 50) {
  const db = await getPool();
  const result = await db
    .request()
    .input('u1', sql.NVarChar(20), user1)
    .input('u2', sql.NVarChar(20), user2)
    .input('limit', sql.Int, limit)
    .query(
      `SELECT TOP(@limit) FromUsername, ToUsername, EncryptedMessage, EncryptedForSender, Signature, SentAt
       FROM Messages
       WHERE (FromUsername = @u1 AND ToUsername = @u2) OR (FromUsername = @u2 AND ToUsername = @u1)
       ORDER BY SentAt DESC`
    );
  return result.recordset.reverse();
}

// Get distinct users that the given user has ever exchanged messages with
async function getConversationPartners(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('me', sql.NVarChar(20), username)
    .query(
      `SELECT DISTINCT
         CASE WHEN FromUsername = @me THEN ToUsername ELSE FromUsername END AS PartnerUsername
       FROM Messages
       WHERE FromUsername = @me OR ToUsername = @me`
    );
  return result.recordset.map((r) => r.PartnerUsername);
}

// ============================================
// Search users
// ============================================

async function searchUsers(query, currentUsername) {
  const db = await getPool();
  const result = await db
    .request()
    .input('q', sql.NVarChar(20), '%' + query + '%')
    .input('me', sql.NVarChar(20), currentUsername)
    .query('SELECT Username FROM Users WHERE Username LIKE @q AND Username != @me');
  return result.recordset;
}

// ============================================
// Friend request operations
// ============================================

async function sendFriendRequest(fromUsername, toUsername) {
  const db = await getPool();
  // Check if already friends
  const friendCheck = await db
    .request()
    .input('u1', sql.NVarChar(20), fromUsername)
    .input('u2', sql.NVarChar(20), toUsername)
    .query(
      `SELECT Id FROM Friends WHERE (Username1 = @u1 AND Username2 = @u2) OR (Username1 = @u2 AND Username2 = @u1)`
    );
  if (friendCheck.recordset.length > 0) return { error: 'Already friends' };

  // Check if request already exists
  const existing = await db
    .request()
    .input('from', sql.NVarChar(20), fromUsername)
    .input('to', sql.NVarChar(20), toUsername)
    .query(
      `SELECT Id, Status FROM FriendRequests WHERE FromUsername = @from AND ToUsername = @to`
    );
  if (existing.recordset.length > 0) {
    if (existing.recordset[0].Status === 'pending') return { error: 'Request already sent' };
  }

  // Check if the other person already sent us a request -> auto accept
  const reverse = await db
    .request()
    .input('from', sql.NVarChar(20), toUsername)
    .input('to', sql.NVarChar(20), fromUsername)
    .query(
      `SELECT Id, Status FROM FriendRequests WHERE FromUsername = @from AND ToUsername = @to AND Status = 'pending'`
    );
  if (reverse.recordset.length > 0) {
    // Auto accept
    await db
      .request()
      .input('id', sql.Int, reverse.recordset[0].Id)
      .query(`UPDATE FriendRequests SET Status = 'accepted' WHERE Id = @id`);
    const u1 = fromUsername < toUsername ? fromUsername : toUsername;
    const u2 = fromUsername < toUsername ? toUsername : fromUsername;
    await db
      .request()
      .input('u1', sql.NVarChar(20), u1)
      .input('u2', sql.NVarChar(20), u2)
      .query('INSERT INTO Friends (Username1, Username2) VALUES (@u1, @u2)');
    return { status: 'accepted' };
  }

  await db
    .request()
    .input('from', sql.NVarChar(20), fromUsername)
    .input('to', sql.NVarChar(20), toUsername)
    .query(
      `INSERT INTO FriendRequests (FromUsername, ToUsername, Status) VALUES (@from, @to, 'pending')`
    );
  return { status: 'pending' };
}

async function getPendingRequests(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('me', sql.NVarChar(20), username)
    .query(
      `SELECT Id, FromUsername, CreatedAt FROM FriendRequests WHERE ToUsername = @me AND Status = 'pending' ORDER BY CreatedAt DESC`
    );
  return result.recordset;
}

async function getSentRequests(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('me', sql.NVarChar(20), username)
    .query(
      `SELECT Id, ToUsername, Status, CreatedAt FROM FriendRequests WHERE FromUsername = @me ORDER BY CreatedAt DESC`
    );
  return result.recordset;
}

async function acceptFriendRequest(requestId, username) {
  const db = await getPool();
  const req = await db
    .request()
    .input('id', sql.Int, requestId)
    .input('me', sql.NVarChar(20), username)
    .query(`SELECT Id, FromUsername, ToUsername FROM FriendRequests WHERE Id = @id AND ToUsername = @me AND Status = 'pending'`);
  if (req.recordset.length === 0) return { error: 'Request not found' };
  const r = req.recordset[0];
  await db.request().input('id', sql.Int, requestId).query(`UPDATE FriendRequests SET Status = 'accepted' WHERE Id = @id`);
  const u1 = r.FromUsername < r.ToUsername ? r.FromUsername : r.ToUsername;
  const u2 = r.FromUsername < r.ToUsername ? r.ToUsername : r.FromUsername;
  await db
    .request()
    .input('u1', sql.NVarChar(20), u1)
    .input('u2', sql.NVarChar(20), u2)
    .query('INSERT INTO Friends (Username1, Username2) VALUES (@u1, @u2)');
  return { status: 'accepted', friend: r.FromUsername };
}

async function rejectFriendRequest(requestId, username) {
  const db = await getPool();
  await db
    .request()
    .input('id', sql.Int, requestId)
    .input('me', sql.NVarChar(20), username)
    .query(`UPDATE FriendRequests SET Status = 'rejected' WHERE Id = @id AND ToUsername = @me AND Status = 'pending'`);
  return { status: 'rejected' };
}

async function getFriends(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('me', sql.NVarChar(20), username)
    .query(
      `SELECT CASE WHEN Username1 = @me THEN Username2 ELSE Username1 END AS FriendUsername
       FROM Friends
       WHERE Username1 = @me OR Username2 = @me`
    );
  return result.recordset;
}

async function getFriendshipStatus(username1, username2) {
  const db = await getPool();
  // Check if friends
  const friends = await db
    .request()
    .input('u1', sql.NVarChar(20), username1)
    .input('u2', sql.NVarChar(20), username2)
    .query(
      `SELECT Id FROM Friends WHERE (Username1 = @u1 AND Username2 = @u2) OR (Username1 = @u2 AND Username2 = @u1)`
    );
  if (friends.recordset.length > 0) return 'friends';

  // Check pending requests
  const sent = await db
    .request()
    .input('from', sql.NVarChar(20), username1)
    .input('to', sql.NVarChar(20), username2)
    .query(`SELECT Id FROM FriendRequests WHERE FromUsername = @from AND ToUsername = @to AND Status = 'pending'`);
  if (sent.recordset.length > 0) return 'request_sent';

  const recv = await db
    .request()
    .input('from', sql.NVarChar(20), username2)
    .input('to', sql.NVarChar(20), username1)
    .query(`SELECT Id, FromUsername FROM FriendRequests WHERE FromUsername = @from AND ToUsername = @to AND Status = 'pending'`);
  if (recv.recordset.length > 0) return 'request_received';

  return 'none';
}

// ============================================
// Encrypted key backup (cross-browser sync)
// ============================================

async function saveEncryptedKeys(username, encryptedKeys) {
  const db = await getPool();
  await db
    .request()
    .input('username', sql.NVarChar(20), username)
    .input('ek', sql.NVarChar(sql.MAX), encryptedKeys)
    .query('UPDATE Users SET EncryptedKeys = @ek WHERE Username = @username');
}

async function getEncryptedKeys(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input('username', sql.NVarChar(20), username)
    .query('SELECT EncryptedKeys FROM Users WHERE Username = @username');
  const row = result.recordset[0];
  return row ? row.EncryptedKeys : null;
}

module.exports = {
  getPool,
  createUser,
  getUserByUsername,
  updatePublicKey,
  getUserPublicKey,
  createSession,
  getSessionByToken,
  deleteSession,
  saveMessage,
  getMessages,
  getConversationPartners,
  searchUsers,
  sendFriendRequest,
  getPendingRequests,
  getSentRequests,
  acceptFriendRequest,
  rejectFriendRequest,
  getFriends,
  getFriendshipStatus,
  saveEncryptedKeys,
  getEncryptedKeys,
  sql,
};
