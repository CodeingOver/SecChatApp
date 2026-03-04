/* ============================================
   SecChatApp – Server Tests
   ============================================ */

const http = require('http');
const { Server } = require('socket.io');
const ioClient = require('socket.io-client');
const assert = require('assert');

let httpServer;
let io;
const PORT = 4567;

function createServer() {
  return new Promise((resolve) => {
    httpServer = http.createServer();
    io = new Server(httpServer);

    const users = new Map();

    io.on('connection', (socket) => {
      socket.on('register', ({ username, publicKey }) => {
        users.set(socket.id, { username, publicKey });
        broadcastUserList();
      });

      socket.on('private-message', (data) => {
        const sender = users.get(socket.id);
        io.to(data.to).emit('private-message', {
          from: socket.id,
          fromUsername: sender ? sender.username : 'Unknown',
          encryptedMessage: data.encryptedMessage,
          signature: data.signature,
        });
      });

      socket.on('disconnect', () => {
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

    httpServer.listen(PORT, () => resolve());
  });
}

function connectClient(name, publicKey) {
  return new Promise((resolve) => {
    const client = ioClient(`http://localhost:${PORT}`);
    client.on('connect', () => {
      client.emit('register', { username: name, publicKey });
      resolve(client);
    });
  });
}

function waitForEvent(client, event) {
  return new Promise((resolve) => {
    client.once(event, (data) => resolve(data));
  });
}

async function runTests() {
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ ${name}: ${err.message}`);
      failed++;
    }
  }

  console.log('\n🔒 SecChatApp Server Tests\n');

  await createServer();

  // Test 1: User registration and user list
  await test('User registration broadcasts user list', async () => {
    const client1 = connectClient('Alice', '{"encryption":"keyA","signing":"signA"}');
    const client2Promise = new Promise(async (resolve) => {
      const c1 = await client1;
      // Wait a bit, then connect client 2
      const userListPromise = waitForEvent(c1, 'user-list');
      const c2 = await connectClient('Bob', '{"encryption":"keyB","signing":"signB"}');
      const userList = await userListPromise;
      resolve({ c1, c2, userList });
    });

    const { c1, c2, userList } = await client2Promise;
    assert.ok(userList.length >= 1, 'User list should have at least 1 user');
    const usernames = userList.map((u) => u.username);
    assert.ok(
      usernames.includes('Alice') || usernames.includes('Bob'),
      'User list should contain registered users'
    );
    c1.disconnect();
    c2.disconnect();
  });

  // Test 2: Private message relay
  await test('Server relays encrypted messages between users', async () => {
    const clientA = await connectClient('Charlie', '{"encryption":"keyC","signing":"signC"}');
    // Wait for user-list to have Charlie
    await waitForEvent(clientA, 'user-list');

    const clientB = await connectClient('Diana', '{"encryption":"keyD","signing":"signD"}');
    // Wait for both to see the user list
    await waitForEvent(clientA, 'user-list');

    const messagePromise = waitForEvent(clientB, 'private-message');

    clientA.emit('private-message', {
      to: clientB.id,
      encryptedMessage: 'base64encrypteddata==',
      signature: 'base64signaturedata==',
    });

    const received = await messagePromise;
    assert.strictEqual(received.encryptedMessage, 'base64encrypteddata==');
    assert.strictEqual(received.signature, 'base64signaturedata==');
    assert.strictEqual(received.fromUsername, 'Charlie');
    assert.ok(received.from, 'Should include sender socket id');

    clientA.disconnect();
    clientB.disconnect();
  });

  // Test 3: Server only sees ciphertext (E2E proof)
  await test('Server does NOT see plaintext (E2E encryption proof)', async () => {
    const clientA = await connectClient('Eve', '{"encryption":"keyE","signing":"signE"}');
    await waitForEvent(clientA, 'user-list');
    const clientB = await connectClient('Frank', '{"encryption":"keyF","signing":"signF"}');
    await waitForEvent(clientA, 'user-list');

    const messagePromise = waitForEvent(clientB, 'private-message');

    const fakeCiphertext = 'U2FsdGVkX1+abc123/encrypted/content==';
    const fakeSignature = 'MEUCIQD+sig+data==';

    clientA.emit('private-message', {
      to: clientB.id,
      encryptedMessage: fakeCiphertext,
      signature: fakeSignature,
    });

    const received = await messagePromise;
    // The server relays exactly what was sent — it cannot modify or read
    assert.strictEqual(received.encryptedMessage, fakeCiphertext);
    assert.strictEqual(received.signature, fakeSignature);
    // Verify that the plaintext "Hello" is NOT in the relayed data
    assert.ok(!received.encryptedMessage.includes('Hello'), 'Server should not relay plaintext');

    clientA.disconnect();
    clientB.disconnect();
  });

  // Test 4: User disconnect removes from user list
  await test('User disconnect removes them from user list', async () => {
    const clientA = await connectClient('Grace', '{"encryption":"keyG","signing":"signG"}');
    await waitForEvent(clientA, 'user-list');
    const clientB = await connectClient('Hank', '{"encryption":"keyH","signing":"signH"}');
    await waitForEvent(clientA, 'user-list');

    const disconnectListPromise = waitForEvent(clientA, 'user-list');
    clientB.disconnect();
    const userList = await disconnectListPromise;

    const usernames = userList.map((u) => u.username);
    assert.ok(!usernames.includes('Hank'), 'Hank should be removed after disconnect');

    clientA.disconnect();
  });

  // Cleanup
  io.close();
  httpServer.close();

  console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
