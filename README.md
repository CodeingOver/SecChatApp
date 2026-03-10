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

Open your browser at `http://localhost:3000`. Open multiple tabs/browsers to simulate different users.

## Testing

```bash
npm test
```

## Technology Stack

- **Backend**: Node.js, Express, Socket.io
- **Frontend**: HTML, CSS, JavaScript
- **Cryptography**: Web Crypto API (RSA-OAEP 2048-bit, RSASSA-PKCS1-v1_5, SHA-256)
