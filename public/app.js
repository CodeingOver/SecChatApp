/* ============================================
   SecChatApp – Main Application Logic
   ============================================ */

(function () {
  const socket = io();

  // DOM elements
  const loginScreen = document.getElementById('login-screen');
  const chatScreen = document.getElementById('chat-screen');
  const usernameInput = document.getElementById('username-input');
  const joinBtn = document.getElementById('join-btn');
  const myUsernameEl = document.getElementById('my-username');
  const userListEl = document.getElementById('user-list');
  const chatHeader = document.getElementById('chat-with');
  const encryptionBadge = document.getElementById('encryption-badge');
  const messagesEl = document.getElementById('messages');
  const messageInputArea = document.getElementById('message-input-area');
  const messageInput = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');

  // State
  let myUsername = '';
  let myEncryptionKeyPair = null;
  let mySigningKeyPair = null;
  let myEncryptionPublicKeyBase64 = '';
  let mySigningPublicKeyBase64 = '';
  let selectedUserId = null;
  let onlineUsers = []; // [{id, username, encryptionPublicKey, signingPublicKey}]
  // Chat history: { odtherUserId: [{from, text, verified, timestamp}] }
  const chatHistory = {};

  // =========== Login ===========
  joinBtn.addEventListener('click', handleJoin);
  usernameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleJoin();
  });

  async function handleJoin() {
    const name = usernameInput.value.trim();
    if (!name) return;

    joinBtn.disabled = true;
    joinBtn.textContent = 'Generating keys...';

    // Step 1: Generate RSA key pairs (client-side)
    myEncryptionKeyPair = await CryptoModule.generateEncryptionKeyPair();
    mySigningKeyPair = await CryptoModule.generateSigningKeyPair();

    // Step 2: Export public keys for sharing
    myEncryptionPublicKeyBase64 = await CryptoModule.exportPublicKey(myEncryptionKeyPair.publicKey);
    mySigningPublicKeyBase64 = await CryptoModule.exportPublicKey(mySigningKeyPair.publicKey);

    myUsername = name;

    // Step 3: Register with server (send public keys, keep private keys local)
    socket.emit('register', {
      username: name,
      publicKey: JSON.stringify({
        encryption: myEncryptionPublicKeyBase64,
        signing: mySigningPublicKeyBase64,
      }),
    });

    // Switch to chat screen
    loginScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    myUsernameEl.textContent = name;
  }

  // =========== User List ===========
  socket.on('user-list', (users) => {
    onlineUsers = users.filter((u) => u.id !== socket.id);
    renderUserList();
  });

  function renderUserList() {
    userListEl.innerHTML = '';
    if (onlineUsers.length === 0) {
      userListEl.innerHTML = '<div class="no-users">No other users online</div>';
      return;
    }
    onlineUsers.forEach((user) => {
      const el = document.createElement('div');
      el.className = 'user-item' + (user.id === selectedUserId ? ' active' : '');
      el.textContent = user.username;

      // Show unread indicator
      const history = chatHistory[user.id];
      if (history && history.some((m) => m.unread)) {
        const dot = document.createElement('span');
        dot.className = 'unread-dot';
        el.appendChild(dot);
      }

      el.addEventListener('click', () => selectUser(user.id));
      userListEl.appendChild(el);
    });
  }

  function selectUser(userId) {
    selectedUserId = userId;
    const user = onlineUsers.find((u) => u.id === userId);
    if (!user) return;

    chatHeader.textContent = user.username;
    encryptionBadge.classList.remove('hidden');
    messageInputArea.classList.remove('hidden');
    messageInput.focus();

    // Mark messages as read
    if (chatHistory[userId]) {
      chatHistory[userId].forEach((m) => (m.unread = false));
    }

    renderMessages();
    renderUserList();
  }

  // =========== Sending Messages ===========
  sendBtn.addEventListener('click', handleSend);
  messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleSend();
  });

  async function handleSend() {
    const text = messageInput.value.trim();
    if (!text || !selectedUserId) return;

    const recipient = onlineUsers.find((u) => u.id === selectedUserId);
    if (!recipient) return;

    try {
      // Parse recipient's public keys
      const recipientKeys = JSON.parse(recipient.publicKey);
      const recipientEncKey = await CryptoModule.importEncryptionPublicKey(recipientKeys.encryption);

      // Step 1: Hash message with SHA-256 and sign with sender's private key → Digital Signature
      const signature = await CryptoModule.signMessage(mySigningKeyPair.privateKey, text);

      // Step 2: Encrypt plaintext with recipient's public encryption key → Ciphertext
      const encryptedMessage = await CryptoModule.encryptMessage(recipientEncKey, text);

      // Step 3: Send encrypted message + signature to server
      socket.emit('private-message', {
        to: selectedUserId,
        encryptedMessage,
        signature,
      });

      // Store in local chat history
      if (!chatHistory[selectedUserId]) chatHistory[selectedUserId] = [];
      chatHistory[selectedUserId].push({
        from: 'me',
        text,
        verified: true,
        timestamp: Date.now(),
      });

      messageInput.value = '';
      renderMessages();
    } catch (err) {
      console.error('Encryption error:', err);
      addSystemMessage('Failed to encrypt message. Please try again.');
    }
  }

  // =========== Receiving Messages ===========
  socket.on('private-message', async (data) => {
    try {
      // Step 1: Decrypt ciphertext with own private key
      const plaintext = await CryptoModule.decryptMessage(
        myEncryptionKeyPair.privateKey,
        data.encryptedMessage
      );

      // Step 2: Verify digital signature using sender's public signing key
      const sender = onlineUsers.find((u) => u.id === data.from);
      let verified = false;
      if (sender) {
        const senderKeys = JSON.parse(sender.publicKey);
        const senderSignKey = await CryptoModule.importVerificationPublicKey(senderKeys.signing);
        verified = await CryptoModule.verifySignature(senderSignKey, plaintext, data.signature);
      }

      // Store in chat history
      if (!chatHistory[data.from]) chatHistory[data.from] = [];
      chatHistory[data.from].push({
        from: data.fromUsername,
        text: plaintext,
        verified,
        timestamp: Date.now(),
        unread: data.from !== selectedUserId,
      });

      if (data.from === selectedUserId) {
        renderMessages();
      }
      renderUserList();
    } catch (err) {
      console.error('Decryption error:', err);
      if (!chatHistory[data.from]) chatHistory[data.from] = [];
      chatHistory[data.from].push({
        from: data.fromUsername,
        text: '⚠️ Failed to decrypt message',
        verified: false,
        timestamp: Date.now(),
        unread: data.from !== selectedUserId,
      });
      if (data.from === selectedUserId) renderMessages();
      renderUserList();
    }
  });

  // =========== Render Messages ===========
  function renderMessages() {
    messagesEl.innerHTML = '';
    const history = chatHistory[selectedUserId] || [];
    if (history.length === 0) {
      messagesEl.innerHTML =
        '<div class="no-messages">No messages yet. Send an encrypted message!</div>';
      return;
    }
    history.forEach((msg) => {
      const el = document.createElement('div');
      const isMine = msg.from === 'me';
      el.className = 'message ' + (isMine ? 'sent' : 'received');

      const textEl = document.createElement('div');
      textEl.className = 'message-text';
      textEl.textContent = msg.text;

      const metaEl = document.createElement('div');
      metaEl.className = 'message-meta';

      const timeStr = new Date(msg.timestamp).toLocaleTimeString();
      const verifyIcon = msg.verified ? '✅' : '⚠️';
      const verifyText = msg.verified ? 'Verified' : 'Unverified';
      metaEl.innerHTML = `<span class="verify-status ${msg.verified ? 'verified' : 'unverified'}">${verifyIcon} ${verifyText}</span> <span class="time">${timeStr}</span>`;

      el.appendChild(textEl);
      el.appendChild(metaEl);
      messagesEl.appendChild(el);
    });
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function addSystemMessage(text) {
    const el = document.createElement('div');
    el.className = 'message system';
    el.textContent = text;
    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }
})();
