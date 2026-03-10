/* ============================================
   SecChatApp – Main Application Logic
   ============================================ */

(function () {

  // =========== DOM elements ===========
  const authScreen = document.getElementById('auth-screen');
  const chatScreen = document.getElementById('chat-screen');

  // Auth tabs
  const authTabs = document.querySelectorAll('.auth-tab');
  const loginFormEl = document.getElementById('login-form');
  const registerFormEl = document.getElementById('register-form');

  // Login
  const loginUsernameEl = document.getElementById('login-username');
  const loginPasswordEl = document.getElementById('login-password');
  const loginErrorEl = document.getElementById('login-error');
  const loginBtn = document.getElementById('login-btn');

  // Register
  const regUsernameEl = document.getElementById('reg-username');
  const regPasswordEl = document.getElementById('reg-password');
  const regConfirmEl = document.getElementById('reg-confirm');
  const regErrorEl = document.getElementById('reg-error');
  const regBtn = document.getElementById('reg-btn');

  // Chat UI
  const myAvatarEl = document.getElementById('my-avatar');
  const logoutBtn = document.getElementById('logout-btn');
  const searchInput = document.getElementById('search-input');
  const userListEl = document.getElementById('user-list');
  const chatEmptyEl = document.getElementById('chat-empty');
  const chatActiveEl = document.getElementById('chat-active');
  const chatAvatarEl = document.getElementById('chat-avatar');
  const chatWithEl = document.getElementById('chat-with');
  const messagesEl = document.getElementById('messages');
  const messageInput = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');

  // =========== State ===========
  let socket = null;
  let myUsername = '';
  let myEncryptionKeyPair = null;
  let mySigningKeyPair = null;
  let myEncryptionPublicKeyBase64 = '';
  let mySigningPublicKeyBase64 = '';
  let selectedUserId = null;
  let onlineUsers = [];
  let searchQuery = '';
  // chatHistory: { otherUserId: [{from, text, verified, timestamp, unread}] }
  const chatHistory = {};

  // =========== Avatar helpers ===========
  const AVATAR_COLORS = [
    '#0084ff', '#e91e63', '#9c27b0', '#673ab7',
    '#3f51b5', '#009688', '#4caf50', '#ff9800', '#795548', '#f44336',
  ];

  function getAvatarColor(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = Math.imul(31, hash) + name.charCodeAt(i) | 0;
    }
    return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
  }

  function getInitials(name) {
    return name.slice(0, 2).toUpperCase();
  }

  function applyAvatar(el, name) {
    el.style.background = getAvatarColor(name);
    el.textContent = getInitials(name);
  }

  // =========== Toggle password visibility ===========
  document.querySelectorAll('.toggle-password').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.target);
      target.type = target.type === 'password' ? 'text' : 'password';
    });
  });

  // =========== Auth Tab switching ===========
  authTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      authTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      if (tab.dataset.tab === 'login') {
        loginFormEl.classList.remove('hidden');
        registerFormEl.classList.add('hidden');
      } else {
        loginFormEl.classList.add('hidden');
        registerFormEl.classList.remove('hidden');
      }
    });
  });

  // =========== Login ===========
  loginBtn.addEventListener('click', handleLogin);
  loginUsernameEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') loginPasswordEl.focus(); });
  loginPasswordEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleLogin(); });

  async function handleLogin() {
    const username = loginUsernameEl.value.trim();
    const password = loginPasswordEl.value;
    if (!username || !password) {
      showError(loginErrorEl, 'Please enter your username and password.');
      return;
    }
    loginBtn.disabled = true;
    loginBtn.textContent = 'Signing in…';
    loginErrorEl.classList.add('hidden');
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        showError(loginErrorEl, data.error || 'Login failed. Please try again.');
        return;
      }
      await startChat(data.token, data.username);
    } catch {
      showError(loginErrorEl, 'Connection error. Please try again.');
    } finally {
      loginBtn.disabled = false;
      loginBtn.textContent = 'Sign In';
    }
  }

  // =========== Register ===========
  regBtn.addEventListener('click', handleRegister);
  regUsernameEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') regPasswordEl.focus(); });
  regPasswordEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') regConfirmEl.focus(); });
  regConfirmEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleRegister(); });

  async function handleRegister() {
    const username = regUsernameEl.value.trim();
    const password = regPasswordEl.value;
    const confirm = regConfirmEl.value;
    if (!username || !password || !confirm) {
      showError(regErrorEl, 'Please fill in all fields.');
      return;
    }
    if (password !== confirm) {
      showError(regErrorEl, 'Passwords do not match.');
      return;
    }
    regBtn.disabled = true;
    regBtn.textContent = 'Creating account…';
    regErrorEl.classList.add('hidden');
    try {
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        showError(regErrorEl, data.error || 'Registration failed. Please try again.');
        return;
      }
      await startChat(data.token, data.username);
    } catch {
      showError(regErrorEl, 'Connection error. Please try again.');
    } finally {
      regBtn.disabled = false;
      regBtn.textContent = 'Create Account';
    }
  }

  function showError(el, msg) {
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  // =========== Start Chat session ===========
  async function startChat(token, username) {
    myUsername = username;

    // Generate RSA key pairs client-side
    myEncryptionKeyPair = await CryptoModule.generateEncryptionKeyPair();
    mySigningKeyPair = await CryptoModule.generateSigningKeyPair();
    myEncryptionPublicKeyBase64 = await CryptoModule.exportPublicKey(myEncryptionKeyPair.publicKey);
    mySigningPublicKeyBase64 = await CryptoModule.exportPublicKey(mySigningKeyPair.publicKey);

    // Connect socket with auth token
    socket = io({ auth: { token } });

    socket.on('connect', () => {
      socket.emit('register', {
        publicKey: JSON.stringify({
          encryption: myEncryptionPublicKeyBase64,
          signing: mySigningPublicKeyBase64,
        }),
      });
    });

    socket.on('connect_error', (err) => {
      console.error('Socket connection error:', err.message);
    });

    socket.on('user-list', (users) => {
      onlineUsers = users.filter((u) => u.id !== socket.id);
      renderUserList();
    });

    socket.on('private-message', handleIncomingMessage);

    // Set my avatar in sidebar header
    applyAvatar(myAvatarEl, username);

    // Switch to chat screen
    authScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');

    // Pre-fill username for next login
    localStorage.setItem('sca_username', username);
  }

  // =========== Logout ===========
  logoutBtn.addEventListener('click', handleLogout);

  function handleLogout() {
    if (socket) {
      socket.disconnect();
      socket = null;
    }
    myUsername = '';
    myEncryptionKeyPair = null;
    mySigningKeyPair = null;
    selectedUserId = null;
    onlineUsers = [];
    Object.keys(chatHistory).forEach((k) => delete chatHistory[k]);

    chatScreen.classList.add('hidden');
    authScreen.classList.remove('hidden');
    chatEmptyEl.classList.remove('hidden');
    chatActiveEl.classList.add('hidden');
    loginPasswordEl.value = '';
    regUsernameEl.value = '';
    regPasswordEl.value = '';
    regConfirmEl.value = '';
    loginErrorEl.classList.add('hidden');
    regErrorEl.classList.add('hidden');
  }

  // =========== Search ===========
  searchInput.addEventListener('input', () => {
    searchQuery = searchInput.value.toLowerCase().trim();
    renderUserList();
  });

  // =========== User List ===========
  function renderUserList() {
    userListEl.innerHTML = '';
    const filtered = onlineUsers.filter(
      (u) => !searchQuery || u.username.toLowerCase().includes(searchQuery)
    );
    if (filtered.length === 0) {
      userListEl.innerHTML =
        '<div class="no-users">No contacts online.<br>Ask a friend to join!</div>';
      return;
    }
    filtered.forEach((user) => {
      const el = document.createElement('div');
      el.className = 'user-item' + (user.id === selectedUserId ? ' active' : '');

      // Avatar
      const avatarEl = document.createElement('div');
      avatarEl.className = 'avatar';
      applyAvatar(avatarEl, user.username);

      // Info block
      const info = document.createElement('div');
      info.className = 'user-item-info';

      const nameEl = document.createElement('div');
      nameEl.className = 'user-item-name';
      nameEl.textContent = user.username;

      const subEl = document.createElement('div');
      subEl.className = 'user-item-sub';
      const history = chatHistory[user.id];
      const lastMsg = history && history.length > 0 ? history[history.length - 1] : null;
      if (lastMsg) {
        const preview = lastMsg.from === 'me' ? `You: ${lastMsg.text}` : lastMsg.text;
        subEl.textContent = preview.length > 36 ? preview.slice(0, 36) + '…' : preview;
      } else {
        subEl.textContent = '🔐 Encrypted';
      }

      info.appendChild(nameEl);
      info.appendChild(subEl);
      el.appendChild(avatarEl);
      el.appendChild(info);

      // Unread badge
      const unreadCount = history ? history.filter((m) => m.unread).length : 0;
      if (unreadCount > 0) {
        const badge = document.createElement('div');
        badge.className = 'unread-badge';
        badge.textContent = unreadCount;
        el.appendChild(badge);
      }

      el.addEventListener('click', () => selectUser(user.id));
      userListEl.appendChild(el);
    });
  }

  function selectUser(userId) {
    selectedUserId = userId;
    const user = onlineUsers.find((u) => u.id === userId);
    if (!user) return;

    chatWithEl.textContent = user.username;
    applyAvatar(chatAvatarEl, user.username);

    // Mark messages as read
    if (chatHistory[userId]) {
      chatHistory[userId].forEach((m) => (m.unread = false));
    }

    chatEmptyEl.classList.add('hidden');
    chatActiveEl.classList.remove('hidden');
    messageInput.focus();
    renderMessages();
    renderUserList();
  }

  // =========== Sending Messages ===========
  sendBtn.addEventListener('click', handleSend);
  messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleSend(); });

  async function handleSend() {
    const text = messageInput.value.trim();
    if (!text || !selectedUserId) return;

    const recipient = onlineUsers.find((u) => u.id === selectedUserId);
    if (!recipient) return;

    try {
      const recipientKeys = JSON.parse(recipient.publicKey);
      const recipientEncKey = await CryptoModule.importEncryptionPublicKey(recipientKeys.encryption);

      // Sign then encrypt
      const signature = await CryptoModule.signMessage(mySigningKeyPair.privateKey, text);
      const encryptedMessage = await CryptoModule.encryptMessage(recipientEncKey, text);

      socket.emit('private-message', { to: selectedUserId, encryptedMessage, signature });

      if (!chatHistory[selectedUserId]) chatHistory[selectedUserId] = [];
      chatHistory[selectedUserId].push({
        from: 'me',
        text,
        verified: true,
        timestamp: Date.now(),
      });

      messageInput.value = '';
      renderMessages();
      renderUserList();
    } catch (err) {
      console.error('Encryption error:', err);
      addSystemMessage('Failed to encrypt message. Please try again.');
    }
  }

  // =========== Receiving Messages ===========
  async function handleIncomingMessage(data) {
    try {
      // Decrypt with own private key
      const plaintext = await CryptoModule.decryptMessage(
        myEncryptionKeyPair.privateKey,
        data.encryptedMessage
      );

      // Verify signature with sender's public signing key
      const sender = onlineUsers.find((u) => u.id === data.from);
      let verified = false;
      if (sender) {
        const senderKeys = JSON.parse(sender.publicKey);
        const senderSignKey = await CryptoModule.importVerificationPublicKey(senderKeys.signing);
        verified = await CryptoModule.verifySignature(senderSignKey, plaintext, data.signature);
      }

      if (!chatHistory[data.from]) chatHistory[data.from] = [];
      chatHistory[data.from].push({
        from: data.fromUsername,
        text: plaintext,
        verified,
        timestamp: Date.now(),
        unread: data.from !== selectedUserId,
      });

      if (data.from === selectedUserId) renderMessages();
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
  }

  // =========== Render Messages ===========
  function renderMessages() {
    messagesEl.innerHTML = '';
    const history = chatHistory[selectedUserId] || [];
    if (history.length === 0) {
      messagesEl.innerHTML = '<div class="no-messages">Start your encrypted conversation! 🔐</div>';
      return;
    }
    history.forEach((msg) => {
      const isMine = msg.from === 'me';
      const el = document.createElement('div');
      el.className = 'message ' + (isMine ? 'sent' : 'received');

      const textEl = document.createElement('div');
      textEl.className = 'message-text';
      textEl.textContent = msg.text;

      const metaEl = document.createElement('div');
      metaEl.className = 'message-meta';
      const timeStr = new Date(msg.timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
      });
      const verifyIcon = msg.verified ? '✓' : '⚠';
      metaEl.innerHTML =
        `<span class="verify-status ${msg.verified ? 'verified' : 'unverified'}">${verifyIcon}</span>` +
        `<span class="time">${timeStr}</span>`;

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

  // Pre-fill last used username
  const savedUsername = localStorage.getItem('sca_username');
  if (savedUsername) {
    loginUsernameEl.value = savedUsername;
  }

})();
