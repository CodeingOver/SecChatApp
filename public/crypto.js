/* ============================================
  SecChatApp – Module Ma hoa
  Su dung Web Crypto API (native tren trinh duyet, khong thu vien ngoai)
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

  // Tao cap khoa RSA-OAEP dung de ma hoa/giai ma
  async function generateEncryptionKeyPair() {
    return await crypto.subtle.generateKey(
      RSA_ALGORITHM,
      true, // cho phep export
      ['encrypt', 'decrypt']
    );
  }

  // Tao cap khoa RSASSA-PKCS1-v1_5 dung de ky/xac minh
  async function generateSigningKeyPair() {
    return await crypto.subtle.generateKey(
      SIGN_ALGORITHM,
      true,
      ['sign', 'verify']
    );
  }

  // Export public key sang Base64 (de chia se qua server)
  async function exportPublicKey(key) {
    const exported = await crypto.subtle.exportKey('spki', key);
    return arrayBufferToBase64(exported);
  }

  // Import public key ma hoa tu Base64
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

  // Import public key ky tu Base64 (de xac minh)
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

  // Ma hoa tin nhan bang public key cua nguoi nhan (RSA-OAEP)
  async function encryptMessage(publicKey, plaintext) {
    const encoded = new TextEncoder().encode(plaintext);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      encoded
    );
    return arrayBufferToBase64(encrypted);
  }

  // Giai ma tin nhan bang private key cua minh (RSA-OAEP)
  async function decryptMessage(privateKey, ciphertextBase64) {
    const ciphertext = base64ToArrayBuffer(ciphertextBase64);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }

  // Ky tin nhan: hash SHA-256, sau do ky bang private key cua nguoi gui
  async function signMessage(privateKey, plaintext) {
    const encoded = new TextEncoder().encode(plaintext);
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      encoded
    );
    return arrayBufferToBase64(signature);
  }

  // Xac minh chu ky: hash noi dung roi doi chieu voi signature
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

  // Tien ich: ArrayBuffer sang Base64
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Tien ich: Base64 sang ArrayBuffer
  function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Export private key sang JWK (de luu localStorage)
  async function exportPrivateKey(key) {
    return await crypto.subtle.exportKey('jwk', key);
  }

  // Import private key ma hoa tu JWK
  async function importEncryptionPrivateKey(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, RSA_ALGORITHM, true, ['decrypt']);
  }

  // Import public key ma hoa tu JWK
  async function importEncryptionPublicKeyJwk(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, RSA_ALGORITHM, true, ['encrypt']);
  }

  // Import private key ky tu JWK
  async function importSigningPrivateKey(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, SIGN_ALGORITHM, true, ['sign']);
  }

  // Import public key ky tu JWK
  async function importSigningPublicKeyJwk(jwk) {
    return await crypto.subtle.importKey('jwk', jwk, SIGN_ALGORITHM, true, ['verify']);
  }

  // ============================================
  // Ma hoa khoa dua tren mat khau (AES-GCM + PBKDF2)
  // Dung de dong bo khoa giua nhieu trinh duyet
  // ============================================

  // Dan xuat khoa AES-256-GCM tu mat khau bang PBKDF2
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

  // Ma hoa du lieu khoa (chuoi JSON) bang khoa AES-GCM dan xuat tu mat khau
  // Tra ve chuoi JSON: { salt, iv, ciphertext } deu o dang Base64
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

  // Giai ma du lieu khoa bang khoa AES-GCM dan xuat tu mat khau
  // Dau vao: JSON { salt, iv, ciphertext }, dau ra: chuoi JSON chua khoa
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
