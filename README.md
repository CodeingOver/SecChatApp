# 🔒 SecChatApp – Secure Chat Application

A real-time chat application with **End-to-End Encryption (E2E)** using RSA and **Digital Signatures** using SHA-256, built with Node.js and Socket.io.

## Features

- **End-to-End Encryption**: Messages are encrypted on the sender's browser using the recipient's RSA public key and can only be decrypted by the recipient's private key. The server never sees plaintext.
- **Digital Signatures**: Every message is signed with the sender's private key (SHA-256 + RSASSA-PKCS1-v1_5) so the recipient can verify authenticity and integrity.
- **Client-Side Cryptography**: All cryptographic operations (key generation, encryption, decryption, signing, verification) are performed in the browser using the Web Crypto API — no private keys ever leave the client.
- **Real-Time Communication**: Powered by Socket.io for instant message delivery.
- **Visual Security Indicators**: UI shows encryption badges and verification status (✅ Verified / ⚠️ Unverified) for each message.
- **DevTools Protection**: Blocks F12, Ctrl+Shift+I and other shortcuts, detects DevTools via window size / debugger timing / console traps, and shows a full-screen warning overlay when DevTools is detected.
- **Source Code Protection**: JavaScript files are blocked from direct access (403). Scripts are loaded via an encrypted API endpoint and executed from Blob URLs — View Source only shows HTML, Sources tab shows `blob:` URLs instead of file names.
- **API Traffic Encryption**: All REST API request/response payloads are XOR-encrypted with a per-session key. Network tab only shows `{ _enc: "..." }` instead of readable JSON.
- **secureFetch()**: Drop-in fetch wrapper that transparently encrypts outgoing requests and decrypts incoming responses.
- **Cross-Browser Key Sync**: RSA private keys are encrypted with AES-256-GCM (key derived from user password via PBKDF2, 100k iterations) and backed up to the server. Logging in from a new browser restores the same keys — old messages stay decryptable. The server stores only ciphertext and can never decrypt the keys.
- **Offline Messaging**: Messages sent to offline users are stored (encrypted) in SQL Server and delivered when they reconnect.

## How It Works

| Step | Location         | Action                                                    |
| ---- | ---------------- | --------------------------------------------------------- |
| 1    | **Sender (A)**   | Writes message "Hello"                                    |
| 2    | **Sender (A)**   | Signs "Hello" with Private Key(A) → **Digital Signature** |
| 3    | **Sender (A)**   | Encrypts "Hello" with Public Key(B) → **Ciphertext**      |
| 4    | **Server**       | Relays Ciphertext + Signature (cannot read the content)   |
| 5    | **Receiver (B)** | Decrypts Ciphertext with Private Key(B) → "Hello"         |
| 6    | **Receiver (B)** | Verifies Signature with Public Key(A) → ✅ Authentic      |

## Installation

```bash
# Clone the repository
git clone https://github.com/CodeingOver/SecChatApp.git
cd SecChatApp

# Install dependencies
npm install

# Start the server
npm start
```

> **Database**: SQL Server (SQLEXPRESS) with Named Pipes is required. Run `database.sql` in SSMS once to create the `SecChatDB` database and all tables. On every subsequent start, the server automatically runs a schema migration to add any missing columns — no manual ALTER TABLE needed.

Open your browser at `http://localhost:3000`. Open multiple tabs/browsers to simulate different users.

## Testing

```bash
npm test
```

## Technology Stack

- **Backend**: Node.js, Express, Socket.io
- **Frontend**: HTML, CSS, JavaScript (Vanilla)
- **Database**: SQL Server Express (via Named Pipes, `mssql/msnodesqlv8`)
- **Cryptography**: Web Crypto API — RSA-OAEP 2048-bit, RSASSA-PKCS1-v1_5 SHA-256, AES-256-GCM, PBKDF2
- **Server-side hashing**: Node.js `crypto.scrypt` (memory-hard KDF)

## Security Features Summary

| #   | Feature                  | Mechanism                                                     |
| --- | ------------------------ | ------------------------------------------------------------- |
| 1   | E2E Encryption           | RSA-OAEP 2048-bit (Web Crypto API)                            |
| 2   | Digital Signatures       | RSASSA-PKCS1-v1_5 + SHA-256                                   |
| 3   | Password Hashing         | scrypt + 128-bit random salt                                  |
| 4   | Session Auth             | 256-bit random token, checked on every API call               |
| 5   | Cross-Browser Key Sync   | AES-GCM + PBKDF2 encrypted key backup on server               |
| 6   | API Traffic Encryption   | XOR cipher wrapping all JSON payloads                         |
| 7   | Source Protection        | Blob URL script loading, direct JS access blocked (403)       |
| 8   | DevTools Guard           | F12 blocked, window-size & debugger-timing detection          |
| 9   | SQL Injection Prevention | 100% parameterized queries                                    |
| 10  | XSS Prevention           | `textContent` DOM API + server-side HTML entity encoding      |
| 11  | Rate Limiting            | 5 req/min on `/register`, 10 req/min on `/login`              |
| 12  | HTTP Security Headers    | X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy |
