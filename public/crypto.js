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

  // Export private key to JWK (for localStorage persistence)
  async function exportPrivateKey(key) {
    return await crypto.subtle.exportKey('jwk', key);
  }

  // Import private encryption key from JWK
  async function importEncryptionPrivateKey(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, RSA_ALGORITHM, true, ['decrypt']);
  }

  // Import public encryption key from JWK
  async function importEncryptionPublicKeyJwk(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, RSA_ALGORITHM, true, ['encrypt']);
  }

  // Import private signing key from JWK
  async function importSigningPrivateKey(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, SIGN_ALGORITHM, true, ['sign']);
  }

  // Import public signing key from JWK
  async function importSigningPublicKeyJwk(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, SIGN_ALGORITHM, true, ['verify']);
  }

  // ============================================
  // Password-based key encryption (AES-GCM + PBKDF2)
  // Used for cross-browser key synchronization
  // ============================================

  // Derive AES-256-GCM key from password using PBKDF2
  async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Encrypt key material (JSON string) with password-derived AES-GCM key
  // Returns JSON string: { salt, iv, ciphertext } all Base64
  async function encryptKeysWithPassword(keysJsonString, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveKeyFromPassword(password, salt);
    const encoded = new TextEncoder().encode(keysJsonString);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, encoded
    );
    return JSON.stringify({
      salt: arrayBufferToBase64(salt.buffer),
      iv: arrayBufferToBase64(iv.buffer),
      ciphertext: arrayBufferToBase64(ciphertext),
    });
  }

  // Decrypt key material with password-derived AES-GCM key
  // Input: JSON string { salt, iv, ciphertext }, returns JSON string of keys
  async function decryptKeysWithPassword(encryptedString, password) {
    const { salt, iv, ciphertext } = JSON.parse(encryptedString);
    const saltBuf = new Uint8Array(base64ToArrayBuffer(salt));
    const ivBuf = new Uint8Array(base64ToArrayBuffer(iv));
    const ctBuf = base64ToArrayBuffer(ciphertext);
    const aesKey = await deriveKeyFromPassword(password, saltBuf);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuf }, aesKey, ctBuf
    );
    return new TextDecoder().decode(decrypted);
  }

  return {
    generateEncryptionKeyPair,
    generateSigningKeyPair,
    exportPublicKey,
    exportPrivateKey,
    importEncryptionPublicKey,
    importEncryptionPublicKeyJwk,
    importEncryptionPrivateKey,
    importVerificationPublicKey,
    importSigningPrivateKey,
    importSigningPublicKeyJwk,
    encryptMessage,
    decryptMessage,
    signMessage,
    verifySignature,
    encryptKeysWithPassword,
    decryptKeysWithPassword,
  };
})();
