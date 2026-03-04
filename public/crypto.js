/* ============================================
   SecChatApp – Cryptographic Module
   Uses Web Crypto API (browser-native, no external libs)
   ============================================ */

const CryptoModule = (() => {
  const RSA_ALGORITHM = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  };

  const SIGN_ALGORITHM = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  };

  // Generate RSA-OAEP key pair for encryption/decryption
  async function generateEncryptionKeyPair() {
    return await crypto.subtle.generateKey(
      RSA_ALGORITHM,
      true, // extractable
      ['encrypt', 'decrypt']
    );
  }

  // Generate RSASSA-PKCS1-v1_5 key pair for signing/verification
  async function generateSigningKeyPair() {
    return await crypto.subtle.generateKey(
      SIGN_ALGORITHM,
      true,
      ['sign', 'verify']
    );
  }

  // Export public key to Base64 (for sharing via server)
  async function exportPublicKey(key) {
    const exported = await crypto.subtle.exportKey('spki', key);
    return arrayBufferToBase64(exported);
  }

  // Import a public encryption key from Base64
  async function importEncryptionPublicKey(base64Key) {
    const binaryKey = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'spki',
      binaryKey,
      RSA_ALGORITHM,
      true,
      ['encrypt']
    );
  }

  // Import a public signing key from Base64 (for verification)
  async function importVerificationPublicKey(base64Key) {
    const binaryKey = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'spki',
      binaryKey,
      SIGN_ALGORITHM,
      true,
      ['verify']
    );
  }

  // Encrypt a message with recipient's public key (RSA-OAEP)
  async function encryptMessage(publicKey, plaintext) {
    const encoded = new TextEncoder().encode(plaintext);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encoded
    );
    return arrayBufferToBase64(encrypted);
  }

  // Decrypt a message with own private key (RSA-OAEP)
  async function decryptMessage(privateKey, ciphertextBase64) {
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }

  // Sign a message: Hash with SHA-256, then sign with sender's private key
  async function signMessage(privateKey, plaintext) {
    const encoded = new TextEncoder().encode(plaintext);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      encoded
    );
    return arrayBufferToBase64(signature);
  }

  // Verify signature: hash the decrypted message and compare with signature
  async function verifySignature(publicKey, plaintext, signatureBase64) {
    const encoded = new TextEncoder().encode(plaintext);
    const signature = base64ToArrayBuffer(signatureBase64);
    return await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      publicKey,
      signature,
      encoded
    );
  }

  // Utility: ArrayBuffer to Base64
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Utility: Base64 to ArrayBuffer
  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  return {
    generateEncryptionKeyPair,
    generateSigningKeyPair,
    exportPublicKey,
    importEncryptionPublicKey,
    importVerificationPublicKey,
    encryptMessage,
    decryptMessage,
    signMessage,
    verifySignature,
  };
})();
