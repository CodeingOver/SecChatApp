/* ============================================
   SecChatApp – Main Application Logic
   (Messenger-like: Friends, Search, Chat)
   ============================================ */

(function () {

  // =========== API Shield: Encrypt requests & decrypt responses ===========
  // The cipherKey is fetched once from server; all API traffic is XOR-encrypted
  // so the Network tab in DevTools only shows encrypted payloads.
  let _cipherKey = null;

  function _xorCipher(text, key) {
    const keyBytes = [];
    for (let k = 0; k < key.length; k++) keyBytes.push(key.charCodeAt(k));
    // Encode text to UTF-8 bytes
    const textBytes = new TextEncoder().encode(text);
    const out = new Uint8Array(textBytes.length);
    for (let i = 0; i < textBytes.length; i++) {
      out[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    // Convert to base64
    let binary = '';
    for (let i = 0; i < out.length; i++) binary += String.fromCharCode(out[i]);
    return btoa(binary);
  }

  function _xorDecipher(b64, key) {
    const keyBytes = [];
    for (let k = 0; k < key.length; k++) keyBytes.push(key.charCodeAt(k));
    const raw = atob(b64);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
      out[i] = raw.charCodeAt(i) ^ keyBytes[i % keyBytes.length];
    }
    return new TextDecoder().decode(out);
  }

  // Fetch cipher key from server (called once before any API call)
  async function _ensureCipherKey() {
    if (_cipherKey) return;
    const r = await fetch('/api/cipher-key');
    _cipherKey = await r.text();
  }

  // secureFetch: drop-in replacement for fetch() that encrypts API traffic.
  // - Request body is XOR-encrypted before sending → Network shows { _enc: "..." }
  // - Response body is XOR-decrypted automatically → returns normal Response
  async function secureFetch(url, options = {}) {
    await _ensureCipherKey();
    const opts = Object.assign({}, options);

    // Encrypt request body if present
    if (opts.body && typeof opts.body === 'string') {
      opts.body = JSON.stringify({ _enc: _xorCipher(opts.body, _cipherKey) });
    }

    const response = await fetch(url, opts);

    // Decrypt response body
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const envelope = await response.json();
      if (envelope && envelope._enc) {
        const plainJson = _xorDecipher(envelope._enc, _cipherKey);
        const parsed = JSON.parse(plainJson);
        // Return a synthetic Response with the original status
        return new Response(JSON.stringify(parsed), {
          status: response.status,
          statusText: response.statusText,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      // If no _enc wrapper, return as-is (shouldn't happen normally)
      return new Response(JSON.stringify(envelope), {
        status: response.status,
        statusText: response.statusText,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return response;
  }

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
  const chatEmptyEl = document.getElementById('chat-empty');
  const chatActiveEl = document.getElementById('chat-active');
  const chatAvatarEl = document.getElementById('chat-avatar');
  const chatWithEl = document.getElementById('chat-with');
  const addFriendHeaderBtn = document.getElementById('add-friend-header-btn');
  const messagesEl = document.getElementById('messages');
  const messageInput = document.getElementById('message-input');
  const sendBtn = document.getElementById('send-btn');

  // Sidebar tabs
  const sidebarTabs = document.querySelectorAll('.sidebar-tab');
  const tabChats = document.getElementById('tab-chats');
  const tabSearch = document.getElementById('tab-search');
  const friendsListEl = document.getElementById('friends-list');
  const searchInput = document.getElementById('search-input');
  const searchResultsEl = document.getElementById('search-results');

  // Friend requests
  const friendRequestsBtn = document.getElementById('friend-requests-btn');
  const frBadge = document.getElementById('fr-badge');
  const frPanel = document.getElementById('friend-requests-panel');
  const frCloseBtn = document.getElementById('fr-close-btn');
  const frListEl = document.getElementById('fr-list');

  // =========== State ===========
  let socket = null;
  let authToken = '';
  let myUsername = '';
  let myEncryptionKeyPair = null;
  let mySigningKeyPair = null;
  let myEncryptionPublicKeyBase64 = '';
  let mySigningPublicKeyBase64 = '';
  let selectedUser = null; // { username, socketId, publicKey, online }
  let friendsList = []; // [{ username, online, socketId, publicKey }]
  let strangersList = []; // non-friends we've chatted with
  let pendingRequests = [];
  let searchDebounce = null;
  // chatHistory: { username: [{from, text, verified, timestamp, unread}] }
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
      const res = await secureFetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        showError(loginErrorEl, data.error || 'Login failed. Please try again.');
        return;
      }
      await startChat(data.token, data.username, password);
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
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      showError(regErrorEl, 'Username can only contain letters, numbers, and underscores.');
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
      const res = await secureFetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        showError(regErrorEl, data.error || 'Registration failed. Please try again.');
        return;
      }
      showSuccess(regErrorEl, 'Registration successful! Signing you in...');
      await new Promise((resolve) => setTimeout(resolve, 700));
      await startChat(data.token, data.username, password);
    } catch {
      showError(regErrorEl, 'Connection error. Please try again.');
    } finally {
      regBtn.disabled = false;
      regBtn.textContent = 'Create Account';
    }
  }

  function showError(el, msg) {
    el.classList.remove('form-success');
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  function showSuccess(el, msg) {
    el.classList.add('form-success');
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  // =========== API helpers ===========
  function apiHeaders() {
    return { 'Content-Type': 'application/json', 'Authorization': authToken };
  }

  // =========== Start Chat session ===========
  async function startChat(token, username, password) {
    authToken = token;
    myUsername = username;

    // 1) Try to load persisted RSA keys from localStorage
    const storedKeys = localStorage.getItem('sca_keys_' + username);
    let keysLoaded = false;
    if (storedKeys) {
      try {
        const keys = JSON.parse(storedKeys);
        myEncryptionKeyPair = {
          publicKey: await CryptoModule.importEncryptionPublicKeyJwk(keys.encPub),
          privateKey: await CryptoModule.importEncryptionPrivateKey(keys.encPriv),
        };
        mySigningKeyPair = {
          publicKey: await CryptoModule.importSigningPublicKeyJwk(keys.sigPub),
          privateKey: await CryptoModule.importSigningPrivateKey(keys.sigPriv),
        };
        keysLoaded = true;
      } catch (e) {
        console.warn('Failed to restore keys from localStorage:', e);
        localStorage.removeItem('sca_keys_' + username);
      }
    }

    // 2) If no localStorage keys and password available, try server backup
    if (!keysLoaded && password) {
      try {
        const bkRes = await secureFetch('/api/backup-keys', { headers: apiHeaders() });
        if (bkRes.ok) {
          const bkData = await bkRes.json();
          const decryptedJson = await CryptoModule.decryptKeysWithPassword(bkData.encryptedKeys, password);
          const keys = JSON.parse(decryptedJson);
          myEncryptionKeyPair = {
            publicKey: await CryptoModule.importEncryptionPublicKeyJwk(keys.encPub),
            privateKey: await CryptoModule.importEncryptionPrivateKey(keys.encPriv),
          };
          mySigningKeyPair = {
            publicKey: await CryptoModule.importSigningPublicKeyJwk(keys.sigPub),
            privateKey: await CryptoModule.importSigningPrivateKey(keys.sigPriv),
          };
          keysLoaded = true;
        }
      } catch (e) {
        console.warn('Failed to restore keys from server backup:', e);
      }
    }

    // 3) If still no keys, generate new ones
    if (!keysLoaded) {
      myEncryptionKeyPair = await CryptoModule.generateEncryptionKeyPair();
      mySigningKeyPair = await CryptoModule.generateSigningKeyPair();
    }

    // 4) Persist keys to localStorage whenever they were newly loaded or generated
    if (!storedKeys || !keysLoaded) {
      const keysToStore = {
        encPub: await CryptoModule.exportPrivateKey(myEncryptionKeyPair.publicKey),
        encPriv: await CryptoModule.exportPrivateKey(myEncryptionKeyPair.privateKey),
        sigPub: await CryptoModule.exportPrivateKey(mySigningKeyPair.publicKey),
        sigPriv: await CryptoModule.exportPrivateKey(mySigningKeyPair.privateKey),
      };
      localStorage.setItem('sca_keys_' + username, JSON.stringify(keysToStore));

      // 5) Backup encrypted keys to server if password available
      if (password) {
        try {
          const encrypted = await CryptoModule.encryptKeysWithPassword(JSON.stringify(keysToStore), password);
          await secureFetch('/api/backup-keys', {
            method: 'POST',
            headers: apiHeaders(),
            body: JSON.stringify({ encryptedKeys: encrypted }),
          });
        } catch (e) {
          console.warn('Failed to backup keys to server:', e);
        }
      }
    }

    myEncryptionPublicKeyBase64 = await CryptoModule.exportPublicKey(myEncryptionKeyPair.publicKey);
    mySigningPublicKeyBase64 = await CryptoModule.exportPublicKey(mySigningKeyPair.publicKey);

    // Save public key to server via REST (ensures it's in DB for offline messaging)
    const myPublicKeyJson = JSON.stringify({
      encryption: myEncryptionPublicKeyBase64,
      signing: mySigningPublicKeyBase64,
    });
    secureFetch('/api/update-public-key', {
      method: 'POST',
      headers: apiHeaders(),
      body: JSON.stringify({ publicKey: myPublicKeyJson }),
    }).catch((e) => console.warn('Failed to save public key to server:', e));

    // Connect socket with auth token
    socket = io({ auth: { token } });

    socket.on('connect', () => {
      socket.emit('register', {
        publicKey: JSON.stringify({
          encryption: myEncryptionPublicKeyBase64,
          signing: mySigningPublicKeyBase64,
        }),
      });
      // Load friends, conversations and pending requests
      loadFriends();
      loadConversations();
      loadPendingRequests();
    });

    socket.on('connect_error', (err) => {
      console.error('Socket connection error:', err.message);
    });

    // Keep user-list for backward compatibility (online tracking)
    socket.on('user-list', () => {
      loadFriends();
    });

    socket.on('private-message', handleIncomingMessage);

    // Friend events
    socket.on('friend-request-received', () => {
      loadPendingRequests();
    });

    socket.on('friend-accepted', async () => {
      await loadFriends();
      await loadConversations();
      loadPendingRequests();
      updateHeaderFriendBtn();
    });

    socket.on('friend-status-changed', async () => {
      await loadFriends();
      await loadConversations();
      updateHeaderFriendBtn();
    });

    // Set my avatar in sidebar header
    applyAvatar(myAvatarEl, username);

    // Switch to chat screen
    authScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');

    localStorage.setItem('sca_username', username);
    localStorage.setItem('sca_token', token);  // persist session for F5 reload
  }

  // =========== Load Friends ===========
  async function loadFriends() {
    try {
      const res = await secureFetch('/api/friends', { headers: apiHeaders() });
      if (!res.ok) return;
      friendsList = await res.json();
      renderFriendsList();
      // Update selected user's online status if they're a friend
      if (selectedUser) {
        const updated = friendsList.find((f) => f.username === selectedUser.username);
        if (updated) {
          selectedUser.online = updated.online;
          selectedUser.socketId = updated.socketId;
          selectedUser.publicKey = updated.publicKey;
          updateInputState();
        }
      }
    } catch (err) {
      console.error('Failed to load friends:', err);
    }
  }

  // =========== Load Conversations (strangers we've chatted with) ===========
  async function loadConversations() {
    try {
      const res = await secureFetch('/api/conversations', { headers: apiHeaders() });
      if (!res.ok) return;
      const all = await res.json();
      // Keep only non-friends (friends are already in friendsList)
      strangersList = all.filter((u) => u.friendshipStatus !== 'friends');
      renderFriendsList();
      // Update selected user if they're a stranger
      if (selectedUser) {
        const updated = strangersList.find((s) => s.username === selectedUser.username);
        if (updated) {
          selectedUser.online = updated.online;
          selectedUser.socketId = updated.socketId;
          selectedUser.publicKey = updated.publicKey;
          updateInputState();
        }
      }
    } catch (err) {
      console.error('Failed to load conversations:', err);
    }
  }

  // =========== Load Pending Requests ===========
  async function loadPendingRequests() {
    try {
      const res = await secureFetch('/api/friend-requests', { headers: apiHeaders() });
      if (!res.ok) return;
      pendingRequests = await res.json();
      updateFrBadge();
      renderFriendRequests();
    } catch (err) {
      console.error('Failed to load friend requests:', err);
    }
  }

  function updateFrBadge() {
    if (pendingRequests.length > 0) {
      frBadge.textContent = pendingRequests.length;
      frBadge.classList.remove('hidden');
    } else {
      frBadge.classList.add('hidden');
    }
  }

  // =========== Logout ===========
  logoutBtn.addEventListener('click', handleLogout);

  function handleLogout() {
    if (socket) {
      socket.disconnect();
      socket = null;
    }
    authToken = '';
    myUsername = '';
    myEncryptionKeyPair = null;
    mySigningKeyPair = null;
    selectedUser = null;
    friendsList = [];
    strangersList = [];
    pendingRequests = [];
    Object.keys(chatHistory).forEach((k) => delete chatHistory[k]);

    chatScreen.classList.add('hidden');
    authScreen.classList.remove('hidden');
    chatEmptyEl.classList.remove('hidden');
    chatActiveEl.classList.add('hidden');
    frPanel.classList.add('hidden');
    loginPasswordEl.value = '';
    regUsernameEl.value = '';
    regPasswordEl.value = '';
    regConfirmEl.value = '';
    loginErrorEl.classList.add('hidden');
    regErrorEl.classList.add('hidden');
    localStorage.removeItem('sca_token');
  }

  // =========== Sidebar Tabs ===========
  sidebarTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      sidebarTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      if (tab.dataset.stab === 'chats') {
        tabChats.classList.remove('hidden');
        tabSearch.classList.add('hidden');
      } else {
        tabChats.classList.add('hidden');
        tabSearch.classList.remove('hidden');
        searchInput.focus();
      }
    });
  });

  // =========== Friend Requests Panel ===========
  friendRequestsBtn.addEventListener('click', () => {
    frPanel.classList.toggle('hidden');
  });
  frCloseBtn.addEventListener('click', () => {
    frPanel.classList.add('hidden');
  });

  // =========== Search Users ===========
  searchInput.addEventListener('input', () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(doSearch, 300);
  });

  async function doSearch() {
    const q = searchInput.value.trim();
    if (q.length < 1) {
      searchResultsEl.innerHTML = '<div class="no-users">Type a username to search</div>';
      return;
    }
    try {
      const res = await secureFetch(`/api/search?q=${encodeURIComponent(q)}`, { headers: apiHeaders() });
      if (!res.ok) return;
      const results = await res.json();
      renderSearchResults(results);
    } catch (err) {
      console.error('Search error:', err);
    }
  }

  function renderSearchResults(results) {
    searchResultsEl.innerHTML = '';
    if (results.length === 0) {
      searchResultsEl.innerHTML = '<div class="no-users">No users found</div>';
      return;
    }
    results.forEach((user) => {
      const el = document.createElement('div');
      el.className = 'user-item search-result-item';

      const avatarEl = document.createElement('div');
      avatarEl.className = 'avatar';
      applyAvatar(avatarEl, user.username);

      const info = document.createElement('div');
      info.className = 'user-item-info';
      const nameEl = document.createElement('div');
      nameEl.className = 'user-item-name';
      nameEl.textContent = user.username;
      const subEl = document.createElement('div');
      subEl.className = 'user-item-sub';

      info.appendChild(nameEl);
      info.appendChild(subEl);
      el.appendChild(avatarEl);
      el.appendChild(info);

      // Always allow clicking to chat
      el.style.cursor = 'pointer';
      el.addEventListener('click', () => openChatWithUser(user.username));

      if (user.friendshipStatus === 'friends') {
        subEl.textContent = '✓ Friends';
        subEl.style.color = '#4caf50';
      } else if (user.friendshipStatus === 'request_sent') {
        subEl.textContent = '⏳ Request sent';
        const addBtn = document.createElement('button');
        addBtn.className = 'btn-small btn-sent';
        addBtn.textContent = '⏳ Sent';
        addBtn.disabled = true;
        el.appendChild(addBtn);
      } else if (user.friendshipStatus === 'request_received') {
        subEl.textContent = '📩 Sent you a request';
        subEl.style.color = '#0084ff';
        const viewBtn = document.createElement('button');
        viewBtn.className = 'btn-small btn-accept';
        viewBtn.textContent = 'Accept';
        viewBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          frPanel.classList.remove('hidden');
        });
        el.appendChild(viewBtn);
      } else {
        subEl.textContent = 'User';
        const addBtn = document.createElement('button');
        addBtn.className = 'btn-small btn-add-friend';
        addBtn.textContent = '+ Add';
        addBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          sendFriendRequest(user.username, addBtn);
        });
        el.appendChild(addBtn);
      }

      searchResultsEl.appendChild(el);
    });
  }

  async function sendFriendRequest(toUsername, btn) {
    btn.disabled = true;
    btn.textContent = '...';
    try {
      const res = await secureFetch('/api/friend-request', {
        method: 'POST',
        headers: apiHeaders(),
        body: JSON.stringify({ toUsername }),
      });
      const data = await res.json();
      if (!res.ok) {
        btn.textContent = data.error || 'Error';
        return;
      }
      if (data.status === 'accepted') {
        btn.classList.add('hidden');
        loadFriends();
        loadConversations();
      } else {
        btn.textContent = '⏳ Đã gửi';
        btn.className = 'btn-small btn-sent';
        btn.disabled = true;
      }
    } catch {
      btn.textContent = 'Error';
    }
  }

  // =========== Render Friends List ===========
  function renderFriendsList() {
    friendsListEl.innerHTML = '';
    const hasAnyone = friendsList.length > 0 || strangersList.length > 0;
    if (!hasAnyone) {
      friendsListEl.innerHTML =
        '<div class="no-users">No conversations yet.<br>Use Search to find people to chat with!</div>';
      return;
    }

    // Sort: online first, then alphabetically
    const sortedFriends = [...friendsList].sort((a, b) => {
      if (a.online !== b.online) return b.online ? 1 : -1;
      return a.username.localeCompare(b.username);
    });
    const sortedStrangers = [...strangersList].sort((a, b) => {
      if (a.online !== b.online) return b.online ? 1 : -1;
      return a.username.localeCompare(b.username);
    });

    // Render friends first, then strangers
    if (sortedFriends.length > 0) {
      sortedFriends.forEach((friend) => renderChatItem(friend, false));
    }
    if (sortedStrangers.length > 0) {
      if (sortedFriends.length > 0) {
        const divider = document.createElement('div');
        divider.className = 'chat-section-label';
        divider.textContent = 'Người lạ';
        friendsListEl.appendChild(divider);
      }
      sortedStrangers.forEach((stranger) => renderChatItem(stranger, true));
    }
  }

  function renderChatItem(person, isStranger) {
    const el = document.createElement('div');
    el.className = 'user-item' + (selectedUser && selectedUser.username === person.username ? ' active' : '');

    const avatarEl = document.createElement('div');
    avatarEl.className = 'avatar';
    applyAvatar(avatarEl, person.username);

    const statusDot = document.createElement('div');
    statusDot.className = 'status-dot ' + (person.online ? 'online' : 'offline');

    const avatarWrap = document.createElement('div');
    avatarWrap.className = 'avatar-wrap';
    avatarWrap.appendChild(avatarEl);
    avatarWrap.appendChild(statusDot);

    const info = document.createElement('div');
    info.className = 'user-item-info';

    const nameEl = document.createElement('div');
    nameEl.className = 'user-item-name';
    nameEl.textContent = person.username;

    const subEl = document.createElement('div');
    subEl.className = 'user-item-sub';
    const history = chatHistory[person.username];
    const lastMsg = history && history.length > 0 ? history[history.length - 1] : null;
    if (lastMsg) {
      const preview = lastMsg.from === 'me' ? `You: ${lastMsg.text}` : lastMsg.text;
      subEl.textContent = preview.length > 36 ? preview.slice(0, 36) + '…' : preview;
    } else if (isStranger) {
      subEl.textContent = '👤 Người lạ';
    } else {
      subEl.textContent = person.online ? '🟢 Online' : '⚫ Offline';
    }

    info.appendChild(nameEl);
    info.appendChild(subEl);
    el.appendChild(avatarWrap);
    el.appendChild(info);

    const unreadCount = history ? history.filter((m) => m.unread).length : 0;
    if (unreadCount > 0) {
      const badge = document.createElement('div');
      badge.className = 'unread-badge';
      badge.textContent = unreadCount;
      el.appendChild(badge);
    }

    el.addEventListener('click', () => selectFriend(person));
    friendsListEl.appendChild(el);
  }

  // =========== Render Friend Requests ===========
  function renderFriendRequests() {
    frListEl.innerHTML = '';
    if (pendingRequests.length === 0) {
      frListEl.innerHTML = '<div class="no-users">No pending requests</div>';
      return;
    }
    pendingRequests.forEach((req) => {
      const el = document.createElement('div');
      el.className = 'fr-item';

      const avatarEl = document.createElement('div');
      avatarEl.className = 'avatar avatar-sm';
      applyAvatar(avatarEl, req.FromUsername);

      const info = document.createElement('div');
      info.className = 'fr-item-info';
      const nameEl = document.createElement('div');
      nameEl.className = 'fr-item-name';
      nameEl.textContent = req.FromUsername;
      const timeEl = document.createElement('div');
      timeEl.className = 'fr-item-time';
      timeEl.textContent = new Date(req.CreatedAt).toLocaleDateString();
      info.appendChild(nameEl);
      info.appendChild(timeEl);

      const actions = document.createElement('div');
      actions.className = 'fr-actions';

      const acceptBtn = document.createElement('button');
      acceptBtn.className = 'btn-small btn-accept';
      acceptBtn.textContent = 'Accept';
      acceptBtn.addEventListener('click', () => respondToRequest(req.Id, 'accept', el));

      const rejectBtn = document.createElement('button');
      rejectBtn.className = 'btn-small btn-reject';
      rejectBtn.textContent = 'Reject';
      rejectBtn.addEventListener('click', () => respondToRequest(req.Id, 'reject', el));

      actions.appendChild(acceptBtn);
      actions.appendChild(rejectBtn);

      el.appendChild(avatarEl);
      el.appendChild(info);
      el.appendChild(actions);
      frListEl.appendChild(el);
    });
  }

  async function respondToRequest(requestId, action, el) {
    try {
      const res = await secureFetch(`/api/friend-request/${requestId}/${action}`, {
        method: 'POST',
        headers: apiHeaders(),
      });
      if (res.ok) {
        el.remove();
        loadPendingRequests();
        if (action === 'accept') loadFriends();
      }
    } catch (err) {
      console.error('Error responding to request:', err);
    }
  }

  // =========== Open chat with any user (from search) ===========
  async function openChatWithUser(username) {
    // If already a friend, use friend data
    const friend = friendsList.find((f) => f.username === username);
    if (friend) {
      selectFriend(friend);
      return;
    }
    // Otherwise fetch user status from server
    try {
      const res = await secureFetch(`/api/user-status/${encodeURIComponent(username)}`, { headers: apiHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      selectFriend(data);
    } catch (err) {
      console.error('Failed to get user status:', err);
    }
  }

  // =========== Select Friend to Chat ===========
  function selectFriend(friend) {
    selectedUser = {
      username: friend.username,
      socketId: friend.socketId,
      publicKey: friend.publicKey,
      online: friend.online,
    };

    chatWithEl.textContent = friend.username;
    applyAvatar(chatAvatarEl, friend.username);

    // Show/hide Add Friend button based on friendship status
    const isStranger = !friendsList.find((f) => f.username === friend.username);
    const stranger = strangersList.find((s) => s.username === friend.username);
    addFriendHeaderBtn.onclick = null;
    if (isStranger) {
      addFriendHeaderBtn.classList.remove('hidden');
      const status = stranger ? stranger.friendshipStatus : 'none';
      if (status === 'request_sent') {
        addFriendHeaderBtn.textContent = '⏳ Đã gửi';
        addFriendHeaderBtn.className = 'btn-small btn-sent';
        addFriendHeaderBtn.disabled = true;
      } else if (status === 'request_received') {
        addFriendHeaderBtn.textContent = '✅ Chấp nhận';
        addFriendHeaderBtn.className = 'btn-small btn-accept';
        addFriendHeaderBtn.disabled = false;
        addFriendHeaderBtn.onclick = () => sendFriendRequest(friend.username, addFriendHeaderBtn);
      } else {
        addFriendHeaderBtn.textContent = '👤 Kết bạn';
        addFriendHeaderBtn.className = 'btn-small btn-add-friend';
        addFriendHeaderBtn.disabled = false;
        addFriendHeaderBtn.onclick = () => sendFriendRequest(friend.username, addFriendHeaderBtn);
      }
    } else {
      addFriendHeaderBtn.classList.add('hidden');
    }

    // Mark messages as read
    if (chatHistory[friend.username]) {
      chatHistory[friend.username].forEach((m) => (m.unread = false));
    }

    chatEmptyEl.classList.add('hidden');
    chatActiveEl.classList.remove('hidden');

    updateInputState();

    // Load chat history from DB if not already loaded
    if (!chatHistory[friend.username] || chatHistory[friend.username].length === 0) {
      loadChatHistory(friend.username);
    } else {
      renderMessages();
    }
    renderFriendsList();
  }

  // Enable/disable input based on whether recipient has a public key
  function updateInputState() {
    if (!selectedUser) return;
    if (!selectedUser.publicKey) {
      messageInput.disabled = true;
      sendBtn.disabled = true;
      messageInput.placeholder = `Waiting for ${selectedUser.username} to log in before messaging…`;
    } else {
      messageInput.disabled = false;
      sendBtn.disabled = false;
      messageInput.placeholder = 'Type a message…';
      messageInput.focus();
    }
  }

  // Re-evaluate the Add Friend button in the chat header after friend list changes
  function updateHeaderFriendBtn() {
    if (!selectedUser) return;
    const nowFriend = friendsList.find((f) => f.username === selectedUser.username);
    if (nowFriend) {
      // Became a friend — hide the button
      addFriendHeaderBtn.classList.add('hidden');
    }
  }

  // =========== Load Chat History from Database ===========
  async function loadChatHistory(username) {
    try {
      const res = await secureFetch(`/api/messages/${encodeURIComponent(username)}`, { headers: apiHeaders() });
      if (!res.ok) return;
      const messages = await res.json();
      if (messages.length === 0) {
        renderMessages();
        return;
      }
      if (!chatHistory[username]) chatHistory[username] = [];
      // Only add messages from DB that aren't already in local history
      const existingCount = chatHistory[username].length;
      if (existingCount === 0) {
        for (const msg of messages) {
          const isMine = msg.FromUsername === myUsername;
          let text = '🔒 Encrypted message (cannot decrypt)';
          let verified = false;
          // Try to decrypt messages addressed to me
          if (!isMine) {
            try {
              text = await CryptoModule.decryptMessage(myEncryptionKeyPair.privateKey, msg.EncryptedMessage);
              // Try to verify signature
              if (msg.Signature) {
                const senderFriend = friendsList.find((f) => f.username === msg.FromUsername)
                               || strangersList.find((f) => f.username === msg.FromUsername);
                const pubKeyStr = senderFriend ? senderFriend.publicKey : null;
                if (pubKeyStr) {
                  const senderKeys = JSON.parse(pubKeyStr);
                  const senderSignKey = await CryptoModule.importVerificationPublicKey(senderKeys.signing);
                  verified = await CryptoModule.verifySignature(senderSignKey, text, msg.Signature);
                }
              }
            } catch (e) {
              // Can't decrypt (different key session) - show placeholder
            }
          } else {
            // Try to decrypt our own copy (EncryptedForSender)
            if (msg.EncryptedForSender) {
              try {
                text = await CryptoModule.decryptMessage(myEncryptionKeyPair.privateKey, msg.EncryptedForSender);
                verified = true; // We sent it, so it's implicitly verified
              } catch (e) {
                text = '🔒 Sent message (encrypted for recipient)';
              }
            } else {
              text = '🔒 Sent message (encrypted for recipient)';
            }
          }
          chatHistory[username].push({
            from: isMine ? 'me' : msg.FromUsername,
            text,
            verified,
            timestamp: new Date(msg.SentAt).getTime(),
          });
        }
      }
      if (selectedUser && selectedUser.username === username) renderMessages();
      renderFriendsList();
    } catch (err) {
      console.error('Failed to load chat history:', err);
    }
  }

  // =========== Sending Messages ===========
  sendBtn.addEventListener('click', handleSend);
  messageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleSend(); });

  async function handleSend() {
    const text = messageInput.value.trim();
    if (!text || !selectedUser) return;

    // Get the recipient's public key (from online socket or stored in DB)
    let recipientPublicKeyStr = selectedUser.publicKey;
    if (!recipientPublicKeyStr) {
      try {
        const res = await secureFetch(`/api/public-key/${encodeURIComponent(selectedUser.username)}`, { headers: apiHeaders() });
        if (res.ok) {
          const data = await res.json();
          recipientPublicKeyStr = data.publicKey;
          selectedUser.publicKey = recipientPublicKeyStr;
        }
      } catch (e) { /* ignore */ }
    }

    if (!recipientPublicKeyStr) {
      addSystemMessage('Cannot send message: recipient has no public key yet (they need to log in at least once).');
      return;
    }

    try {
      const recipientKeys = JSON.parse(recipientPublicKeyStr);
      const recipientEncKey = await CryptoModule.importEncryptionPublicKey(recipientKeys.encryption);

      const signature = await CryptoModule.signMessage(mySigningKeyPair.privateKey, text);
      const encryptedMessage = await CryptoModule.encryptMessage(recipientEncKey, text);
      const encryptedForSender = await CryptoModule.encryptMessage(myEncryptionKeyPair.publicKey, text);

      if (selectedUser.online && selectedUser.socketId) {
        // Online: send via socket for real-time delivery
        socket.emit('private-message', {
          to: selectedUser.socketId,
          toUsername: selectedUser.username,
          encryptedMessage,
          encryptedForSender,
          signature,
        });
      } else {
        // Offline: send via REST API (saved to DB for later)
        await secureFetch('/api/send-message', {
          method: 'POST',
          headers: apiHeaders(),
          body: JSON.stringify({
            toUsername: selectedUser.username,
            encryptedMessage,
            encryptedForSender,
            signature,
          }),
        });
      }

      if (!chatHistory[selectedUser.username]) chatHistory[selectedUser.username] = [];
      chatHistory[selectedUser.username].push({
        from: 'me',
        text,
        verified: true,
        timestamp: Date.now(),
      });

      messageInput.value = '';
      renderMessages();
      renderFriendsList();
    } catch (err) {
      console.error('Encryption error:', err);
      addSystemMessage('Failed to encrypt message. Please try again.');
    }
  }

  // =========== Receiving Messages ===========
  async function handleIncomingMessage(data) {
    try {
      const plaintext = await CryptoModule.decryptMessage(
        myEncryptionKeyPair.privateKey,
        data.encryptedMessage
      );

      // Verify signature (check friends first, then use sender's publicKey from message)
      let verified = false;
      const senderFriend = friendsList.find((f) => f.socketId === data.from);
      const pubKeyStr = (senderFriend && senderFriend.publicKey) || data.senderPublicKey;
      if (pubKeyStr) {
        const senderKeys = JSON.parse(pubKeyStr);
        const senderSignKey = await CryptoModule.importVerificationPublicKey(senderKeys.signing);
        verified = await CryptoModule.verifySignature(senderSignKey, plaintext, data.signature);
      }

      const senderUsername = data.fromUsername;
      if (!chatHistory[senderUsername]) chatHistory[senderUsername] = [];
      chatHistory[senderUsername].push({
        from: senderUsername,
        text: plaintext,
        verified,
        timestamp: Date.now(),
        unread: !selectedUser || selectedUser.username !== senderUsername,
      });

      if (selectedUser && selectedUser.username === senderUsername) renderMessages();
      renderFriendsList();
    } catch (err) {
      console.error('Decryption error:', err);
      const senderUsername = data.fromUsername;
      if (!chatHistory[senderUsername]) chatHistory[senderUsername] = [];
      chatHistory[senderUsername].push({
        from: senderUsername,
        text: '⚠️ Failed to decrypt message',
        verified: false,
        timestamp: Date.now(),
        unread: !selectedUser || selectedUser.username !== senderUsername,
      });
      if (selectedUser && selectedUser.username === senderUsername) renderMessages();
      renderFriendsList();
    }
  }

  // =========== Render Messages ===========
  function renderMessages() {
    messagesEl.innerHTML = '';
    if (!selectedUser) return;
    const history = chatHistory[selectedUser.username] || [];
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

  // =========== Auto-login after F5 (restore session from localStorage) ===========
  (async function tryAutoLogin() {
    const savedToken = localStorage.getItem('sca_token');
    if (!savedToken) return;
    try {
      const res = await secureFetch('/api/me', { headers: { Authorization: savedToken } });
      if (!res.ok) {
        localStorage.removeItem('sca_token');
        return;
      }
      const data = await res.json();
      await startChat(savedToken, data.username);
    } catch (e) {
      localStorage.removeItem('sca_token');
    }
  })();

})();
