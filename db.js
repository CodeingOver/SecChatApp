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
    .query('SELECT Username, PasswordHash, Salt FROM Users WHERE Username = @username');
  return result.recordset[0] || null;
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
// Message operations (luu lich su tin nhan)
// ============================================

async function saveMessage(fromUsername, toUsername, encryptedMessage, signature) {
  const db = await getPool();
  await db
    .request()
    .input('from', sql.NVarChar(20), fromUsername)
    .input('to', sql.NVarChar(20), toUsername)
    .input('msg', sql.NVarChar(sql.MAX), encryptedMessage)
    .input('sig', sql.NVarChar(sql.MAX), signature || null)
    .query(
      'INSERT INTO Messages (FromUsername, ToUsername, EncryptedMessage, Signature) VALUES (@from, @to, @msg, @sig)'
    );
}

module.exports = {
  getPool,
  createUser,
  getUserByUsername,
  createSession,
  getSessionByToken,
  deleteSession,
  saveMessage,
  sql,
};
