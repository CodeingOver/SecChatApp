const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static(path.join(__dirname, 'public')));

// Store connected users: { socketId: { username, publicKey } }
const users = new Map();

io.on('connection', (socket) => {
  console.log(`[Server] New connection: ${socket.id}`);

  // User registers with username and public key
  socket.on('register', ({ username, publicKey }) => {
    users.set(socket.id, { username, publicKey });
    console.log(`[Server] User registered: ${username} (${socket.id})`);

    // Broadcast updated user list (id, username, publicKey) to all clients
    broadcastUserList();
  });

  // Relay encrypted private message from sender to recipient
  socket.on('private-message', (data) => {
    const sender = users.get(socket.id);
    const senderName = sender ? sender.username : 'Unknown';

    console.log(`[Server] Relaying encrypted message from ${senderName} to ${data.to}`);
    console.log(`[Server] Ciphertext (truncated): ${data.encryptedMessage.substring(0, 80)}...`);
    console.log(`[Server] Signature (truncated): ${data.signature.substring(0, 80)}...`);
    console.log('[Server] *** Server CANNOT read the message content (E2E encrypted) ***');

    io.to(data.to).emit('private-message', {
      from: socket.id,
      fromUsername: senderName,
      encryptedMessage: data.encryptedMessage,
      signature: data.signature,
    });
  });

  socket.on('disconnect', () => {
    const user = users.get(socket.id);
    if (user) {
      console.log(`[Server] User disconnected: ${user.username}`);
    }
    users.delete(socket.id);
    broadcastUserList();
  });
});

function broadcastUserList() {
  const userList = [];
  for (const [id, { username, publicKey }] of users) {
    userList.push({ id, username, publicKey });
  }
  io.emit('user-list', userList);
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`[Server] SecChatApp running on http://localhost:${PORT}`);
});

module.exports = { app, server, io };
