# 📘 TÀI LIỆU KIẾN TRÚC AN TOÀN VÀ BẢO MẬT THÔNG TIN

## Ứng dụng: **SecChatApp – Secure Chat Application**

### Mô tả tổng quan

SecChatApp là ứng dụng nhắn tin bảo mật dạng web sử dụng **mã hóa đầu-cuối (End-to-End Encryption – E2E)** dựa trên hệ mật **RSA** kết hợp **chữ ký số (Digital Signature)**.

Server chỉ đóng vai trò **relay** – chuyển tiếp bản mã đã được mã hóa mà **không bao giờ có khả năng đọc nội dung tin nhắn**.

**Công nghệ sử dụng:**

| Thành phần               | Công nghệ                                         |
| ------------------------ | ------------------------------------------------- |
| Backend                  | Node.js, Express, Socket.io                       |
| Frontend                 | HTML/CSS/JS (Vanilla)                             |
| Mã hóa                   | Web Crypto API (trình duyệt native)               |
| Database                 | SQL Server (via Named Pipes, `mssql/msnodesqlv8`) |
| Giao tiếp thời gian thực | WebSocket (Socket.io)                             |

---

## 📐 KIẾN TRÚC TỔNG THỂ

```
┌──────────────────────┐         ┌──────────────────────┐
│     Client A         │         │     Client B         │
│  (Trình duyệt)      │         │  (Trình duyệt)      │
│                      │         │                      │
│  ┌─────────────┐     │         │     ┌─────────────┐  │
│  │ crypto.js   │     │         │     │ crypto.js   │  │
│  │ (Web Crypto │     │         │     │ (Web Crypto │  │
│  │  API)       │     │         │     │  API)       │  │
│  └──────┬──────┘     │         │     └──────┬──────┘  │
│         │            │         │            │         │
│  RSA-OAEP Encrypt    │         │   RSA-OAEP Decrypt   │
│  RSASSA Sign         │         │   RSASSA Verify      │
│         │            │         │            │         │
│         ▼            │         │            ▼         │
│  [Ciphertext+Sig]────┼────►────┼────[Ciphertext+Sig] │
│                      │   WS    │                      │
└──────────────────────┘  /REST  └──────────────────────┘
            │                              │
            └──────────┐  ┌────────────────┘
                       ▼  ▼
              ┌────────────────────┐
              │     Server.js      │
              │  (Express+Socket)  │
              │                    │
              │  ⚠ CHỈ thấy bản   │
              │  mã (ciphertext)   │
              │  KHÔNG đọc được    │
              │  nội dung gốc      │
              │                    │
              │  ┌──────────────┐  │
              │  │  SQL Server  │  │
              │  │  (SecChatDB) │  │
              │  │  Named Pipes │  │
              │  └──────────────┘  │
              └────────────────────┘
```

---

# ⭕ CHAPTER 1: INFORMATION SECURITY OVERVIEW – Tổng quan An ninh Thông tin

## 1.1. Tại sao SecChatApp cần bảo mật?

Trong bối cảnh các ứng dụng nhắn tin phổ biến (Messenger, Zalo, ...), dữ liệu tin nhắn thường đi qua máy chủ trung gian. Nếu máy chủ bị tấn công, toàn bộ nội dung tin nhắn có thể bị lộ. SecChatApp giải quyết vấn đề này bằng cách đảm bảo rằng **ngay cả khi server bị xâm nhập, kẻ tấn công vẫn không thể đọc nội dung tin nhắn** vì chúng đã được mã hóa đầu-cuối (E2E).

## 1.2. Ba thành phần CIA trong SecChatApp

SecChatApp đáp ứng bộ ba nguyên tắc an ninh thông tin **CIA Triad**:

| Nguyên tắc                    | Mô tả                                             | Triển khai trong SecChatApp                                                                                             |
| ----------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Confidentiality** (Bảo mật) | Chỉ người gửi và người nhận mới đọc được tin nhắn | Mã hóa RSA-OAEP 2048-bit. Server chỉ lưu/chuyển tiếp ciphertext, không có private key để giải mã                        |
| **Integrity** (Toàn vẹn)      | Tin nhắn không bị sửa đổi trên đường truyền       | Chữ ký số RSASSA-PKCS1-v1_5 với SHA-256: người nhận xác minh tính toàn vẹn bằng public key của người gửi                |
| **Availability** (Sẵn sàng)   | Hệ thống luôn sẵn sàng phục vụ                    | Hỗ trợ nhắn tin offline: khi người nhận không trực tuyến, tin nhắn được lưu DB (dạng ciphertext) và gửi khi họ quay lại |

## 1.3. Chiến lược Phòng thủ nhiều lớp (Defense-in-Depth)

SecChatApp triển khai chiến lược **phòng thủ nhiều lớp**, không dựa vào một cơ chế bảo mật duy nhất:

```
┌─────────────────────────────────────────────────┐
│ Lớp 1: Xác thực người dùng                     │
│   - Đăng ký/đăng nhập (username + password)     │
│   - Mật khẩu được hash bằng scrypt + salt       │
│   - Session token 256-bit cho mỗi phiên         │
├─────────────────────────────────────────────────┤
│ Lớp 2: Kiểm soát truy cập                      │
│   - Token-based API authorization               │
│   - Socket.io middleware authentication          │
│   - Tách biệt REST endpoint theo quyền          │
├─────────────────────────────────────────────────┤
│ Lớp 3: Mã hóa đầu-cuối (E2E Encryption)        │
│   - RSA-OAEP 2048-bit cho bảo mật               │
│   - Chữ ký số RSASSA-PKCS1-v1_5 cho toàn vẹn   │
│   - Mỗi user có 2 cặp key riêng biệt           │
├─────────────────────────────────────────────────┤
│ Lớp 4: Kiến trúc Zero-Knowledge Server          │
│   - Server không bao giờ thấy plaintext          │
│   - Private key chỉ tồn tại ở client            │
│   - DB chỉ lưu ciphertext + signature           │
├─────────────────────────────────────────────────┤
│ Lớp 5: Bảo mật dữ liệu lưu trữ (Data-at-Rest) │
│   - Tin nhắn được lưu dưới dạng mã hóa trong DB │
│   - Key lưu trong localStorage (JWK format)     │
│   - Encrypted Key Backup trên server (AES-GCM)  │
│   - SQL Server kết nối qua Named Pipes (local)  │
└─────────────────────────────────────────────────┘
```

### Khi một lớp thất bại:

| Kịch bản tấn công        | Lớp bị phá | Lớp còn lại bảo vệ                                               |
| ------------------------ | ---------- | ---------------------------------------------------------------- |
| Hacker chiếm được server | Lớp 2      | Lớp 3, 4: Dữ liệu trong DB chỉ là ciphertext, không decrypt được |
| Lộ database              | Lớp 5      | Lớp 1: Mật khẩu đã hash (scrypt); Lớp 3: Tin nhắn đã mã hóa RSA  |
| Lộ session token         | Lớp 2      | Lớp 3: Không có private key vẫn không đọc được tin nhắn cũ       |
| Man-in-the-Middle        | Lớp 2      | Lớp 3: Nội dung đã mã hóa; Chữ ký số phát hiện thay đổi          |

---

# 🔒 CHAPTER 2: CRYPTOGRAPHY – Mã hóa

## 2.1. Tổng quan hệ thống mã hóa trong SecChatApp

SecChatApp sử dụng **mã hóa bất đối xứng (Asymmetric Encryption)** hoàn toàn, triển khai qua **Web Crypto API** – API mã hóa native của trình duyệt, không sử dụng thư viện bên thứ ba.

### Bản đồ thuật toán:

| Mục đích            | Thuật toán         | Chi tiết                                                 |
| ------------------- | ------------------ | -------------------------------------------------------- |
| **Mã hóa tin nhắn** | RSA-OAEP           | Modulus: 2048 bit, Hash: SHA-256, Public exponent: 65537 |
| **Chữ ký số**       | RSASSA-PKCS1-v1_5  | Modulus: 2048 bit, Hash: SHA-256, Public exponent: 65537 |
| **Hash mật khẩu**   | scrypt             | Key length: 64 bytes, Salt: 128-bit random               |
| **Token phiên**     | crypto.randomBytes | 256-bit (32 bytes), CSPRNG                               |
| **Salt**            | crypto.randomBytes | 128-bit (16 bytes), CSPRNG                               |

### Tại sao chọn RSA-OAEP thay vì RSA-PKCS1-v1_5 cho mã hóa?

RSA-OAEP (Optimal Asymmetric Encryption Padding) an toàn hơn RSA-PKCS1-v1_5 vì:

- Chống được **Bleichenbacher's chosen-ciphertext attack**
- Sử dụng **padding ngẫu nhiên** → cùng plaintext cho ra ciphertext khác nhau mỗi lần
- Được khuyến nghị bởi NIST và là tiêu chuẩn hiện đại

## 2.2. Mã hóa khóa công khai (Public Key Cryptography)

### 2.2.1. Cấu trúc và luồng hoạt động

Mỗi người dùng sở hữu **2 cặp key (4 key tổng cộng)**:

```
Người dùng (Client-Side)
├── Encryption Key Pair (RSA-OAEP 2048-bit)
│   ├── Public Key  → Chia sẻ qua server (dùng để mã hóa)
│   └── Private Key → Chỉ lưu local (dùng để giải mã)
│
└── Signing Key Pair (RSASSA-PKCS1-v1_5 2048-bit)
    ├── Public Key  → Chia sẻ qua server (dùng để xác minh chữ ký)
    └── Private Key → Chỉ lưu local (dùng để ký)
```

#### Triển khai trong `crypto.js`:

**Sinh cặp key mã hóa:**

```javascript
const RSA_ALGORITHM = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 65537
  hash: "SHA-256",
};

async function generateEncryptionKeyPair() {
  return await crypto.subtle.generateKey(RSA_ALGORITHM, true, [
    "encrypt",
    "decrypt",
  ]);
}
```

**Sinh cặp key chữ ký:**

```javascript
const SIGN_ALGORITHM = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

async function generateSigningKeyPair() {
  return await crypto.subtle.generateKey(SIGN_ALGORITHM, true, [
    "sign",
    "verify",
  ]);
}
```

### 2.2.2. Quy trình mã hóa tin nhắn (Encryption Flow)

```
Alice muốn gửi tin cho Bob:

1. Alice lấy Public Key (encryption) của Bob từ server
2. Alice mã hóa tin nhắn bằng RSA-OAEP với Public Key của Bob
3. Alice cũng mã hóa tin nhắn bằng RSA-OAEP với Public Key của chính mình
   → (EncryptedForSender – để đọc lại tin nhắn đã gửi sau khi F5)
4. Alice ký tin nhắn gốc bằng Private Key (signing) của mình
5. Gửi: {encryptedMessage, encryptedForSender, signature}

Bob nhận được:
6. Bob giải mã encryptedMessage bằng Private Key (encryption) của mình
7. Bob xác minh signature bằng Public Key (signing) của Alice
```

#### Code minh họa trong `app.js` → `handleSend()`:

```javascript
// Bước 1-2: Mã hóa cho người nhận
const recipientEncKey = await CryptoModule.importEncryptionPublicKey(
  recipientKeys.encryption,
);
const encryptedMessage = await CryptoModule.encryptMessage(
  recipientEncKey,
  text,
);

// Bước 3: Mã hóa cho chính mình (EncryptedForSender)
const encryptedForSender = await CryptoModule.encryptMessage(
  myEncryptionKeyPair.publicKey,
  text,
);

// Bước 4: Ký tin nhắn
const signature = await CryptoModule.signMessage(
  mySigningKeyPair.privateKey,
  text,
);
```

#### Hàm mã hóa RSA-OAEP (`crypto.js`):

```javascript
async function encryptMessage(publicKey, plaintext) {
  const encoded = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    encoded,
  );
  return arrayBufferToBase64(encrypted);
}
```

#### Hàm giải mã RSA-OAEP (`crypto.js`):

```javascript
async function decryptMessage(privateKey, ciphertextBase64) {
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const decrypted = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    ciphertext,
  );
  return new TextDecoder().decode(decrypted);
}
```

### 2.2.3. Trao đổi khóa công khai (Public Key Exchange)

Khi đăng nhập, client **XÁC NHẬN** public key với server qua 2 kênh độc lập:

```
Kênh 1 (REST): POST /api/update-public-key
  → Lưu publicKey (encryption + signing) vào DB
  → Mục đích: Để user khác mã hóa tin nhắn khi mình offline

Kênh 2 (WebSocket): socket.emit('register', { publicKey })
  → Lưu publicKey vào bộ nhớ server (in-memory Map)
  → Mục đích: Real-time, nhanh hơn khi user đang online
```

**Cấu trúc Public Key được chia sẻ:**

```json
{
  "encryption": "<RSA-OAEP public key, Base64 SPKI>",
  "signing": "<RSASSA-PKCS1-v1_5 public key, Base64 SPKI>"
}
```

## 2.3. Chữ ký số (Digital Signature)

### 2.3.1. Quy trình ký và xác minh

```
Người gửi (Sign):                    Người nhận (Verify):

  Plaintext                            Plaintext (giải mã được)
      │                                    │
      ▼                                    ▼
  SHA-256 Hash                         SHA-256 Hash
      │                                    │
      ▼                                    ▼
  RSASSA-PKCS1-v1_5                    RSASSA-PKCS1-v1_5
  Sign với Private Key                 Verify với Public Key
      │                                    │
      ▼                                    ▼
  Signature (Base64) ─────────────►  true / false
                   (gửi kèm msg)
```

#### Hàm ký (`crypto.js`):

```javascript
async function signMessage(privateKey, plaintext) {
  const encoded = new TextEncoder().encode(plaintext);
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    encoded,
  );
  return arrayBufferToBase64(signature);
}
```

#### Hàm xác minh (`crypto.js`):

```javascript
async function verifySignature(publicKey, plaintext, signatureBase64) {
  const encoded = new TextEncoder().encode(plaintext);
  const signature = base64ToArrayBuffer(signatureBase64);
  return await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    publicKey,
    signature,
    encoded,
  );
}
```

### 2.3.2. Hiển thị trạng thái xác minh cho người dùng

| Icon | Ý nghĩa                    | Điều kiện                                              |
| ---- | -------------------------- | ------------------------------------------------------ |
| ✓    | Chữ ký hợp lệ              | `verifySignature()` trả về `true`                      |
| ⚠    | Chữ ký không xác minh được | Không có public key của người gửi hoặc verify thất bại |

### 2.3.3. Đảm bảo tính toàn vẹn

Nếu kẻ tấn công (hoặc server) cố tình **sửa đổi ciphertext** trước khi chuyển tiếp:

- Bước giải mã RSA-OAEP sẽ **thất bại** (vì OAEP padding kiểm tra tính toàn vẹn của ciphertext)
- Nếu bằng cách nào đó plaintext bị sửa, chữ ký sẽ **không khớp** → `verifySignature()` trả về `false` → hiển thị ⚠

## 2.4. Hàm băm an toàn (Secure Hash Function)

### 2.4.1. SHA-256 trong mã hóa

SecChatApp sử dụng **SHA-256** ở nhiều nơi:

| Vị trí                           | Mục đích                              |
| -------------------------------- | ------------------------------------- |
| RSA-OAEP hash parameter          | Hash function cho OAEP padding scheme |
| RSASSA-PKCS1-v1_5 hash parameter | Hash tin nhắn trước khi ký            |
| scrypt (server-side)             | Hàm dẫn xuất khóa để hash mật khẩu    |

### 2.4.2. Hash mật khẩu (Password Hashing)

SecChatApp **KHÔNG** lưu mật khẩu dạng plaintext. Thay vào đó:

```javascript
// server.js
const scrypt = promisify(crypto.scrypt);

async function hashPassword(password, salt) {
  const derivedKey = await scrypt(password, salt, 64); // 512-bit derived key
  return derivedKey.toString("hex");
}
```

**scrypt** là hàm dẫn xuất khóa (KDF – Key Derivation Function) được thiết kế:

- **Memory-hard**: Yêu cầu nhiều RAM, chống GPU/ASIC brute-force
- **CPU-intensive**: Chống tấn công song song
- **Salted**: Mỗi user có salt riêng (128-bit random), chống rainbow table

**Schema lưu trữ trong DB:**

```sql
Users (
  Username     NVARCHAR(20),
  PasswordHash NVARCHAR(128),  -- scrypt output, 512-bit hex
  Salt         NVARCHAR(32),   -- 128-bit random hex
  PublicKey    NVARCHAR(MAX),  -- JSON {encryption, signing}
)
```

## 2.5. Số ngẫu nhiên và số giả ngẫu nhiên (Random Numbers)

### 2.5.1. CSPRNG trong SecChatApp

SecChatApp sử dụng **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)** ở cả server và client:

**Server-side** (`server.js` – Node.js `crypto` module):

```javascript
// Salt cho password: 128-bit
const salt = crypto.randomBytes(16).toString("hex");

// Session token: 256-bit
function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}
```

**Client-side** (Web Crypto API):

- `crypto.subtle.generateKey()` sử dụng CSPRNG nội bộ của trình duyệt để sinh cặp RSA key
- RSA-OAEP padding cũng sử dụng random bytes nội bộ

### 2.5.2. Ý nghĩa của tính ngẫu nhiên

| Component     | Kích thước | Mục đích tính ngẫu nhiên                                                 |
| ------------- | ---------- | ------------------------------------------------------------------------ |
| RSA Key Pair  | 2048-bit   | Nếu key có thể đoán được → toàn bộ E2E encryption vô nghĩa               |
| Password Salt | 128-bit    | Nếu salt giống nhau → cùng password cho cùng hash → rainbow table attack |
| Session Token | 256-bit    | Nếu đoán được → chiếm phiên người dùng (session hijacking)               |
| OAEP Padding  | biến đổi   | Cùng plaintext → ciphertext khác nhau mỗi lần (semantic security)        |

## 2.6. Lưu trữ và bảo vệ khóa (Key Management)

### 2.6.1. Vòng đời khóa RSA

```
┌─ Sinh key ──────────────────────────────────────────────┐
│ Lần đầu đăng nhập:                                     │
│   generateEncryptionKeyPair() → {publicKey, privateKey} │
│   generateSigningKeyPair() → {publicKey, privateKey}    │
└──────────────────────────┬──────────────────────────────┘
                           │
┌─ Lưu trữ ───────────────▼──────────────────────────────┐
│ Client (localStorage):                                  │
│   sca_keys_{username} = {                               │
│     encPub: JWK, encPriv: JWK,                          │
│     sigPub: JWK, sigPriv: JWK                           │
│   }                                                     │
│                                                         │
│ Server (SQL Server DB):                                 │
│   Users.PublicKey = JSON {encryption, signing}           │
│   (Chỉ lưu PUBLIC key, KHÔNG BAO GIỜ lưu private key)  │
│                                                         │
│ Server (Encrypted Backup):                              │
│   Users.EncryptedKeys = AES-GCM encrypted JWK           │
│   (Server KHÔNG THỂ giải mã — cần mật khẩu người dùng) │
└──────────────────────────┬──────────────────────────────┘
                           │
┌─ Phục hồi ──────────────▼──────────────────────────────┐
│ Khi F5 / reload / đăng nhập lại:                        │
│   1. Đọc JWK từ localStorage                            │
│   2. Nếu không có → tải bản backup từ server            │
│      → Giải mã bằng AES-GCM (key từ mật khẩu + PBKDF2) │
│   3. Import lại thành CryptoKey objects                  │
│   4. Nếu thất bại → sinh key mới + lưu lại + backup    │
└──────────────────────────┬──────────────────────────────┘
                           │
┌─ Hủy key ────────────────▼──────────────────────────────┐
│ Khi đăng xuất:                                          │
│   myEncryptionKeyPair = null;                            │
│   mySigningKeyPair = null;                               │
│   (key bị xóa khỏi bộ nhớ, nhưng JWK vẫn trong         │
│    localStorage để phục hồi lần sau)                     │
└─────────────────────────────────────────────────────────┘
```

### 2.6.2. Đồng bộ khóa đa trình duyệt (Cross-Browser Key Sync)

Vấn đề: `localStorage` là riêng biệt cho mỗi trình duyệt. Khi người dùng đăng nhập từ Firefox sau khi đã tạo khóa trên Chrome, họ sẽ không giải mã được các tin nhắn cũ.

**Giải pháp: Encrypted Key Backup** – mã hóa RSA private keys bằng AES-GCM với khóa dẫn xuất từ mật khẩu (PBKDF2), lưu trên server.

```
┌─ Backup (khi sinh key mới) ─────────────────────────────┐
│                                                          │
│  Password ──PBKDF2──→ AES-256-GCM Key                   │
│         (100,000 iterations, SHA-256, random salt)       │
│                                                          │
│  JWK Keys JSON ──AES-GCM Encrypt──→ Ciphertext          │
│         (random 12-byte IV)                              │
│                                                          │
│  Gửi lên server: {salt, iv, ciphertext} (tất cả Base64) │
│  Lưu vào: Users.EncryptedKeys                           │
└──────────────────────────────────────────────────────────┘

┌─ Restore (khi đăng nhập trình duyệt mới) ──────────────┐
│                                                          │
│  GET /api/backup-keys → {salt, iv, ciphertext}           │
│                                                          │
│  Password ──PBKDF2──→ AES-256-GCM Key (cùng salt)       │
│  Ciphertext ──AES-GCM Decrypt──→ JWK Keys JSON          │
│  Import JWK → CryptoKey objects → Lưu localStorage       │
└──────────────────────────────────────────────────────────┘
```

**Đảm bảo an toàn (Zero-Knowledge)**:

- Server chỉ lưu **ciphertext** đã mã hóa AES-GCM
- Khóa AES được dẫn xuất từ mật khẩu người dùng bằng **PBKDF2** (100,000 iterations)
- Random **salt** (16 bytes) và **IV** (12 bytes) cho mỗi lần backup
- Server **KHÔNG THỂ** giải mã private keys mà không biết mật khẩu
- Nếu mật khẩu sai → AES-GCM decrypt sẽ thất bại (authentication tag kiểm tra)

**Luồng ưu tiên trong `startChat()`**:

1. Thử `localStorage` (nhanh nhất, không cần mật khẩu)
2. Nếu không có → thử **server backup** (cần mật khẩu để giải mã)
3. Nếu không có backup → **sinh key mới** + backup lên server
4. Auto-login (F5 reload): chỉ dùng localStorage (không có mật khẩu)

### 2.6.3. EncryptedForSender – Mã hóa bản sao cho người gửi

Khi gửi tin nhắn, client mã hóa **2 bản**:

| Trường               | Mã hóa bằng               | Mục đích                                      |
| -------------------- | ------------------------- | --------------------------------------------- |
| `EncryptedMessage`   | Public key **người nhận** | Người nhận giải mã                            |
| `EncryptedForSender` | Public key **người gửi**  | Người gửi đọc lại tin nhắn đã gửi khi refresh |

Đây là cơ chế tương tự **Signal Protocol** – cho phép cả người gửi đọc lại tin nhắn đã gửi mà không cần lưu plaintext.

---

# 💠 CHAPTER 3: ACCESS CONTROL – Kiểm soát truy cập

## 3.1. Quy trình kiểm soát truy cập

SecChatApp thực hiện quy trình kiểm soát truy cập 3 bước:

```
Bước 1: Nhận dạng (Identification)
  → Username (3-20 ký tự)

Bước 2: Xác thực (Authentication)
  → Password → scrypt hash → so sánh với DB
  → timingSafeEqual() để chống timing attack

Bước 3: Ủy quyền (Authorization)
  → Session token kiểm tra ở mọi API endpoint
  → Socket.io middleware xác thực trước khi kết nối
```

## 3.2. Xác thực (Authentication)

### 3.2.1. Đăng ký (Registration)

```
Client                           Server
  │                                │
  │  POST /api/register            │
  │  { username, password }        │
  │───────────────────────────────►│
  │                                │── Validate input (3-20 chars, min 6 password)
  │                                │── Check username unique
  │                                │── salt = randomBytes(16)
  │                                │── hash = scrypt(password, salt, 64)
  │                                │── INSERT Users (username, hash, salt)
  │                                │── token = randomBytes(32)
  │                                │── INSERT Sessions (token, username)
  │  { token, username }           │
  │◄───────────────────────────────│
```

### 3.2.2. Đăng nhập (Login)

```
Client                           Server
  │                                │
  │  POST /api/login               │
  │  { username, password }        │
  │───────────────────────────────►│
  │                                │── user = getUserByUsername(username)
  │                                │── hash = scrypt(password, user.Salt, 64)
  │                                │── crypto.timingSafeEqual(hash, user.PasswordHash)
  │                                │     ↑ Chống timing attack!
  │                                │── token = randomBytes(32)
  │                                │── INSERT Sessions (token, username)
  │  { token, username }           │
  │◄───────────────────────────────│
  │                                │
  │  → Lưu token vào localStorage │
  │  → Sinh RSA keys (hoặc restore│
  │    từ localStorage)            │
  │  → POST /api/update-public-key │
  │  → Socket.io connect           │
```

#### Chống Timing Attack:

```javascript
// server.js
const hashBuf = Buffer.from(hash, "hex");
const storedBuf = Buffer.from(user.PasswordHash, "hex");
if (!crypto.timingSafeEqual(hashBuf, storedBuf)) {
  return res.status(401).json({ error: "Invalid username or password" });
}
```

`timingSafeEqual()` so sánh 2 buffer trong **thời gian cố định** bất kể nội dung, ngăn kẻ tấn công đoán từng byte mật khẩu qua thời gian phản hồi.

### 3.2.3. Xác thực phiên (Session Authentication)

**Token-based Authentication** được áp dụng nhất quán:

```javascript
// Mọi REST API đều kiểm tra:
const token = req.headers.authorization;
if (!token) return res.status(401).json({ error: "Auth required" });
const session = await db.getSessionByToken(token);
if (!session) return res.status(401).json({ error: "Invalid token" });
```

```javascript
// Socket.io middleware:
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication required"));
  const session = await db.getSessionByToken(token);
  if (session) {
    socket.username = session.Username;
    next();
  } else {
    next(new Error("Authentication required"));
  }
});
```

### 3.2.4. Auto-Login (Session Persistence)

```javascript
// Ghi nhớ phiên sau F5/reload:
(async function tryAutoLogin() {
  const savedToken = localStorage.getItem("sca_token");
  if (!savedToken) return;
  const res = await fetch("/api/me", {
    headers: { Authorization: savedToken },
  });
  if (!res.ok) {
    localStorage.removeItem("sca_token");
    return;
  }
  const data = await res.json();
  await startChat(savedToken, data.username);
})();
```

## 3.3. Phương pháp kiểm soát truy cập

SecChatApp sử dụng **mô hình kiểm soát truy cập tùy ý (DAC – Discretionary Access Control)**:

| Tài nguyên        | Quyền truy cập                   | Cơ chế                                       |
| ----------------- | -------------------------------- | -------------------------------------------- |
| Tin nhắn          | Chỉ 2 người trong cuộc hội thoại | E2E encryption – server không đọc được       |
| Danh sách bạn bè  | Chỉ chủ sở hữu                   | Token authorization                          |
| Lời mời kết bạn   | Người gửi và người nhận          | Token + kiểm tra `FromUsername`/`ToUsername` |
| Khóa công khai    | Tất cả user đã đăng nhập         | Cần thiết để mã hóa tin nhắn cho người khác  |
| Tin nhắn trong DB | Server lưu nhưng không đọc được  | Zero-knowledge: chỉ là ciphertext            |

### 3.3.1. Parameterized Queries – Chống SQL Injection

Mọi truy vấn SQL đều sử dụng **parameterized input** thay vì string concatenation:

```javascript
// db.js – Ví dụ: tìm user
async function getUserByUsername(username) {
  const db = await getPool();
  const result = await db
    .request()
    .input("username", sql.NVarChar(20), username) // Parameterized!
    .query(
      "SELECT Username, PasswordHash, Salt, PublicKey FROM Users WHERE Username = @username",
    );
  return result.recordset[0] || null;
}
```

Điều này **ngăn chặn hoàn toàn SQL Injection** vì giá trị input không bao giờ được nối trực tiếp vào câu lệnh SQL.

---

# 🐛 CHAPTER 4: MALICIOUS SOFTWARE & CODE – Phần mềm độc hại

## 4.1. SecChatApp đối phó với mối đe dọa Malware như thế nào?

### 4.1.1. Zero External Dependencies ở Client

Module mã hóa (`crypto.js`) sử dụng **100% Web Crypto API** – API native của trình duyệt:

- **Không có thư viện NPM phía client** → Loại bỏ rủi ro supply chain attack
- **Không eval(), không dynamic import** → Không có vector cho code injection
- **IIFE pattern** → Code chạy trong closure, không pollute global scope

```javascript
// crypto.js
const CryptoModule = (() => {
  // Toàn bộ logic mã hóa nằm trong closure
  // Không thể bị override từ bên ngoài
  return { encryptMessage, decryptMessage, ... };
})();
```

### 4.1.2. Giảm thiểu Attack Surface (Server)

| Biện pháp            | Mô tả                                                          |
| -------------------- | -------------------------------------------------------------- |
| Minimal dependencies | Chỉ 4 packages: `express`, `socket.io`, `mssql`, `msnodesqlv8` |
| Input validation     | Kiểm tra length, required fields ở mọi endpoint                |
| No file upload       | Không có tính năng upload → loại bỏ vector malware upload      |
| Static serving       | `express.static()` chỉ serve thư mục `/public`                 |

## 4.2. Phòng chống Cross-Site Scripting (XSS)

Mặc dù XSS không phải malware truyền thống, đây là vector tấn công nguy hiểm cho ứng dụng web.

SecChatApp triển khai **phòng thủ XSS nhiều lớp (defense-in-depth)**:

### Lớp 1: Client-side – DOM API an toàn

```javascript
// Sử dụng textContent (safe) thay vì innerHTML (unsafe)
nameEl.textContent = person.username;
subEl.textContent = preview;
textEl.textContent = msg.text;
```

`textContent` tự động escape HTML entities, ngăn chặn XSS qua nội dung tin nhắn.

### Lớp 2: Server-side – Input Sanitization (HTML Entity Encoding)

Ngay cả khi client không escape, server cũng **mã hóa các ký tự đặc biệt HTML** trước khi xử lý:

```javascript
// server.js – sanitizeHtml()
function sanitizeHtml(str) {
  if (typeof str !== "string") return str;
  return str.replace(/[<>"'&]/g, (ch) => {
    switch (ch) {
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      case "&":
        return "&amp;";
      default:
        return ch;
    }
  });
}
```

Áp dụng cho: search query, và mọi nơi hiển thị dữ liệu người dùng.

### Lớp 3: Username Format Validation

```javascript
// Chỉ cho phép chữ cái, số, gạch dưới – loại bỏ hoàn toàn XSS qua username
function isValidUsername(username) {
  return /^[a-zA-Z0-9_]+$/.test(username);
}
```

→ Username như `<script>alert(1)</script>` sẽ bị **từ chối ngay** (HTTP 400).

### Lớp 4: HTTP Security Headers

```
X-Content-Type-Options: nosniff    → Ngăn MIME-type sniffing
X-Frame-Options: DENY              → Chống Clickjacking
Referrer-Policy: no-referrer        → Giảm lộ thông tin
Permissions-Policy: camera=()...    → Chặn quyền không cần thiết
```

### Bảng tổng hợp phòng chống XSS:

| Vector tấn công                  | Biện pháp                           | Vị trí          |
| -------------------------------- | ----------------------------------- | --------------- |
| `<script>` trong tin nhắn        | `textContent` thay vì `innerHTML`   | Client (app.js) |
| `<script>` trong username        | Regex whitelist `[a-zA-Z0-9_]`      | Server + Client |
| HTML entities trong search query | `sanitizeHtml()` escape `< > " ' &` | Server          |
| MIME-type confusion              | `X-Content-Type-Options: nosniff`   | HTTP Header     |
| Clickjacking (iframe-based XSS)  | `X-Frame-Options: DENY`             | HTTP Header     |

---

# 😈 CHAPTER 5: DENIAL OF SERVICE (DoS)

## 5.1. Các biện pháp chống DoS trong SecChatApp

### 5.1.1. Rate Limiting – Chống Brute-force

SecChatApp triển khai **rate limiting** theo IP trên các endpoint nhạy cảm:

```javascript
// Rate limiter: giới hạn số lần gọi API theo IP trong cửa sổ thời gian
function rateLimit(windowMs, maxRequests) {
  return (req, res, next) => {
    const ip = req.ip;
    const key = `${req.path}:${ip}`;
    // Nếu vượt quá maxRequests trong windowMs → HTTP 429
    if (record.count > maxRequests) {
      return res.status(429).json({ error: 'Too many requests' });
    }
    next();
  };
}

// Áp dụng:
app.post('/api/register', rateLimit(60000, 5),  ...);  // 5 lần/phút
app.post('/api/login',    rateLimit(60000, 10), ...);  // 10 lần/phút
```

| Endpoint        | Giới hạn         | Mục đích                                 |
| --------------- | ---------------- | ---------------------------------------- |
| `/api/register` | 5 requests/phút  | Chống spam đăng ký, username enumeration |
| `/api/login`    | 10 requests/phút | Chống brute-force password guessing      |

### 5.1.2. Input Validation & Size Limits

| Biện pháp             | Code                                                                        |
| --------------------- | --------------------------------------------------------------------------- |
| Username length limit | `trimmed.length < 3 \|\| trimmed.length > 20`                               |
| Username format       | `/^[a-zA-Z0-9_]+$/` – chỉ chữ cái, số, gạch dưới                            |
| Password minimum      | `password.length < 6`                                                       |
| Message size limit    | `encryptedMessage.length > 51200` → HTTP 400 (tối đa 50KB)                  |
| Search query limit    | `q.length > 50` → trả về [] (giới hạn 50 ký tự)                             |
| Search sanitization   | `sanitizeHtml(q)` – escape HTML entities trước khi truy vấn DB              |
| Search debounce       | `setTimeout(doSearch, 300)` — client-side throttle                          |
| Message limit         | `getMessages(user1, user2, limit = 50)` — giới hạn 50 tin nhắn mỗi lần load |
| Search result limit   | `LIKE @q` với input parameterized                                           |

### 5.1.2. Named Pipes thay vì TCP

Kết nối DB qua **Named Pipes** (local only):

```javascript
connectionString: "Driver={ODBC Driver 17 for SQL Server};Server=np:\\\\.\\pipe\\MSSQL$SQLEXPRESS\\sql\\query;...";
```

- Named Pipes chỉ hoạt động **trên cùng máy** → không thể bị tấn công từ xa vào DB
- Loại bỏ vector **network-based DoS** nhắm vào database port

### 5.1.3. WebSocket Event Validation

Socket.io chỉ xử lý các event đã đăng ký (`register`, `private-message`, `disconnect`). Event lạ sẽ bị bỏ qua.

---

# 🌊 CHAPTER 6: BUFFER OVERFLOW

## 6.1. Phòng chống Buffer Overflow

SecChatApp được viết bằng **JavaScript (Node.js)** – ngôn ngữ quản lý bộ nhớ tự động:

- **Không có pointer arithmetic** → không thể overflow buffer kiểu C/C++
- **Garbage Collector** tự động quản lý bộ nhớ
- **V8 Engine** xử lý bounds checking tự động cho ArrayBuffer/TypedArray

### Nơi sử dụng binary data:

```javascript
// crypto.js – Base64 ↔ ArrayBuffer conversion
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length); // Kích thước cố định theo input
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
```

- `Uint8Array` là TypedArray, có bounds checking
- V8 sẽ throw `RangeError` nếu truy cập ngoài phạm vi

### SQL input length constraints:

```javascript
// db.js – giới hạn kích thước input SQL
.input('username', sql.NVarChar(20), username)     // Max 20 chars
.input('token', sql.NVarChar(64), token)           // Max 64 chars
.input('passwordHash', sql.NVarChar(128), passwordHash)  // Max 128 chars
```

---

# ⚙️ CHAPTER 7: SOFTWARE & OPERATING SYSTEM SECURITY

## 7.1. Xử lý đầu vào chương trình (Input Handling)

### 7.1.1. Validation ở Server-Side

Mọi endpoint đều validate input trước khi xử lý:

```javascript
// Registration – validation đa lớp
if (!username || !password) return res.status(400).json({ error: "..." });
if (trimmed.length < 3 || trimmed.length > 20)
  return res.status(400).json({ error: "..." });
if (!/^[a-zA-Z0-9_]+$/.test(trimmed))
  return res.status(400).json({ error: "..." });
if (password.length < 6) return res.status(400).json({ error: "..." });

// Send message – kiểm tra kích thước
if (!toUsername || !encryptedMessage)
  return res.status(400).json({ error: "Missing fields" });
if (encryptedMessage.length > 51200)
  return res.status(400).json({ error: "Message too large" });

// Search – sanitization + giới hạn
const q = sanitizeHtml((req.query.q || "").trim());
if (q.length > 50) return res.json([]);

// Friend request
if (!toUsername) return res.status(400).json({ error: "toUsername required" });
if (toUsername === session.Username)
  return res.status(400).json({ error: "Cannot add yourself" });
```

### 7.1.2. HTTP Security Headers

Server thiết lập các **HTTP security headers** cho mọi response:

```javascript
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY"); // Chống Clickjacking
  res.setHeader("X-Content-Type-Options", "nosniff"); // Chống MIME sniffing
  res.setHeader("Referrer-Policy", "no-referrer"); // Giảm lộ thông tin
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  res.setHeader("Cache-Control", "no-store"); // Không cache dữ liệu nhạy cảm
  next();
});
```

| Header                    | Chức năng                                              |
| ------------------------- | ------------------------------------------------------ |
| `X-Frame-Options: DENY`   | Ngăn trang bị nhúng trong iframe → chống Clickjacking  |
| `X-Content-Type-Options`  | Ngăn trình duyệt đoán MIME-type → chống mã độc         |
| `Referrer-Policy`         | Không gửi URL gốc khi navigate → bảo vệ privacy        |
| `Permissions-Policy`      | Chặn camera, microphone, GPS → giảm attack surface     |
| `Cache-Control: no-store` | Không lưu response vào cache → bảo vệ dữ liệu nhạy cảm |

### 7.1.3. Phòng thủ lập trình (Defensive Programming)

| Kỹ thuật                         | Ví dụ trong SecChatApp                                      |
| -------------------------------- | ----------------------------------------------------------- |
| **Fail safely**                  | `result.recordset[0] \|\| null` – trả về null thay vì crash |
| **Check return values**          | `if (!res.ok) return;` – kiểm tra mọi HTTP response         |
| **Parameterized queries**        | Tất cả SQL queries dùng `.input()`                          |
| **Error handling**               | `try/catch` around mọi crypto operation và fetch call       |
| **Principle of least privilege** | Socket chỉ nhận events đã đăng ký                           |
| **Rate limiting**                | Giới hạn request trên login/register → chống brute-force    |
| **Input sanitization**           | `sanitizeHtml()` escape HTML entities trên server-side      |

### 7.1.4. Tách biệt Client và Server

```
Client (public/)          Server (server.js)
├── crypto.js             ├── Không có access đến private key
├── app.js                ├── Chỉ relay ciphertext
├── index.html            ├── Hash password (không lưu plaintext)
└── style.css             └── Validate + authorize mọi request
```

**Server KHÔNG BAO GIỜ:**

- Nhận private key từ client
- Giải mã nội dung tin nhắn
- Lưu mật khẩu dạng plaintext
- Thực thi code từ user input

## 7.2. Xử lý I/O an toàn (Secure I/O)

### Output Encoding:

```javascript
// Sử dụng textContent thay vì innerHTML để chống XSS
textEl.textContent = msg.text;
nameEl.textContent = person.username;
```

### JSON Response:

```javascript
// Server chỉ trả về JSON, không render HTML
res.json({ token, username: trimmed });
res.json({ error: "Auth required" });
```

## 7.3. Bảo vệ mã nguồn – Chống truy cập DevTools (Source Code Protection)

SecChatApp triển khai module **`devtools-guard.js`** để ngăn người dùng mở Developer Tools trên trình duyệt, qua đó bảo vệ mã nguồn JavaScript (chứa logic mã hóa) và các khóa mã hóa lưu trong localStorage.

### 7.3.1. Các kỹ thuật chống DevTools

| #   | Kỹ thuật                               | Mô tả                                                                                                      |
| --- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1   | **Chặn phím tắt**                      | Chặn F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C, Ctrl+U (View Source), Ctrl+S (Save Page)               |
| 2   | **Chặn chuột phải**                    | Vô hiệu hóa context menu (`contextmenu` event) để ngăn "Inspect Element"                                   |
| 3   | **Phát hiện qua kích thước cửa sổ**    | So sánh `outerWidth - innerWidth > 160` – khi DevTools mở docked, viewport bị thu nhỏ                      |
| 4   | **Phát hiện qua `debugger` statement** | Đo thời gian thực thi `debugger;` – nếu > 100ms → DevTools đang mở với breakpoint                          |
| 5   | **Phát hiện qua `console.log` trick**  | Định nghĩa getter trên object rồi `console.log()` – getter chỉ bị gọi khi DevTools hiển thị console output |
| 6   | **Chặn kéo thả**                       | Vô hiệu hóa `dragstart` để ngăn kéo hình ảnh/text ra ngoài xem source                                      |

### 7.3.2. Triển khai

**Chặn phím tắt:**

```javascript
const BLOCKED_KEYS = [
  { key: "F12" }, // F12
  { ctrl: true, shift: true, key: "I" }, // Ctrl+Shift+I (Inspect)
  { ctrl: true, shift: true, key: "J" }, // Ctrl+Shift+J (Console)
  { ctrl: true, shift: true, key: "C" }, // Ctrl+Shift+C (Element picker)
  { ctrl: true, key: "U" }, // Ctrl+U (View source)
  { ctrl: true, key: "S" }, // Ctrl+S (Save page)
];

document.addEventListener(
  "keydown",
  function (e) {
    for (const combo of BLOCKED_KEYS) {
      // Kiểm tra tổ hợp Ctrl, Shift, Key
      if (ctrlMatch && shiftMatch && keyMatch) {
        e.preventDefault();
        e.stopPropagation();
        return false;
      }
    }
  },
  true,
); // Capture phase – chặn trước khi event đến các handler khác
```

**Phát hiện DevTools bằng đo thời gian debugger:**

```javascript
function debuggerCheck() {
  const start = performance.now();
  debugger; // Nếu DevTools mở → dừng ở đây
  const duration = performance.now() - start;
  if (duration > 100) {
    onDevToolsDetected(); // DevTools đang mở!
  }
}
setInterval(debuggerCheck, 2000);
```

**Phát hiện DevTools bằng console.log getter trap:**

```javascript
const devtoolsDetector = {};
Object.defineProperty(devtoolsDetector, "id", {
  get: function () {
    onDevToolsDetected(); // Getter chỉ bị gọi khi console đang render
  },
});
setInterval(function () {
  console.log("%c", devtoolsDetector);
  console.clear();
}, 3000);
```

### 7.3.3. Hành động khi phát hiện DevTools

Khi DevTools được phát hiện, ứng dụng hiển thị **overlay cảnh báo toàn màn hình**:

```
┌──────────────────────────────────────┐
│                                      │
│              ⚠️                       │
│    Developer Tools Detected          │
│                                      │
│  Việc mở Developer Tools bị hạn chế │
│  để bảo vệ mã nguồn và khóa mã hóa │
│  Vui lòng đóng DevTools để tiếp tục │
│                                      │
└──────────────────────────────────────┘
```

- Overlay **tự động biến mất** khi người dùng đóng DevTools
- Ứng dụng kiểm tra mỗi 500ms xem DevTools đã đóng chưa

### 7.3.4. Tại sao cần bảo vệ mã nguồn?

| Mối đe dọa                        | Hậu quả nếu không bảo vệ                                  |
| --------------------------------- | --------------------------------------------------------- |
| Xem source code                   | Hiểu logic mã hóa, tìm lỗ hổng                            |
| Truy cập localStorage qua Console | Đánh cắp RSA private key (JWK) → giải mã mọi tin nhắn     |
| Sửa đổi runtime variables         | Thay đổi `myEncryptionKeyPair`, `authToken` → chiếm phiên |
| Inject JavaScript                 | Chèn code đọc plaintext trước khi mã hóa                  |
| Sử dụng Network tab               | Xem cấu trúc API, replay requests                         |

> **Lưu ý:** Đây là biện pháp **ngăn chặn** (deterrent), không phải bảo vệ tuyệt đối. Người dùng có kiến thức sâu vẫn có thể vượt qua (ví dụ: dùng `--auto-open-devtools-for-tabs` flag). Tuy nhiên, nó tạo thêm một lớp bảo vệ trong chiến lược Defense-in-Depth.

## 7.4. Bảo vệ mã nguồn nâng cao – Chống bên thứ 3 (Advanced Source Protection)

Ngoài việc chặn DevTools, SecChatApp còn triển khai **3 lớp bảo vệ bổ sung** để ngăn người dùng lấy mã nguồn JavaScript và kiểm tra API qua Network tab, ngay cả khi sử dụng công cụ bên thứ 3 (curl, Postman, proxy…).

### 7.4.1. Chặn truy cập trực tiếp file JavaScript (Server Middleware)

Tất cả file JavaScript nghiệp vụ (`app.js`, `crypto.js`, `devtools-guard.js`) **không thể truy cập trực tiếp** qua URL:

```
GET /app.js         → 403 Forbidden ("// Access Denied")
GET /crypto.js      → 403 Forbidden
GET /devtools-guard.js → 403 Forbidden
GET /style.css      → 200 OK (CSS vẫn truy cập được bình thường)
```

**Triển khai (server.js):**

```javascript
const PROTECTED_SCRIPTS = ["app.js", "crypto.js", "devtools-guard.js"];

app.use((req, res, next) => {
  const filename = path.basename(req.path);
  if (PROTECTED_SCRIPTS.includes(filename)) {
    return res.status(403).send("// Access Denied");
  }
  next();
});
```

→ Ngay cả khi dùng `curl http://localhost:3000/app.js` hoặc gõ trực tiếp URL trên trình duyệt, người dùng chỉ nhận được `403`.

### 7.4.2. Tải script mã hóa qua Blob URL (Encrypted Script Loading)

Thay vì dùng `<script src="app.js">`, HTML chỉ chứa một **inline loader nhỏ** tải script qua API mã hóa:

```
┌─────────────────────────────────────────────────────────────┐
│  Luồng tải script                                           │
│                                                             │
│  Browser ──► GET /api/load-scripts?nonce=abc123             │
│          ◄── { scripts: [{name, content: "XOR encrypted"}]} │
│                                                             │
│  Client   ──► XOR giải mã bằng nonce                       │
│           ──► Tạo Blob URL → blob:http://localhost:3000/... │
│           ──► Chèn <script src="blob:..."> vào DOM          │
└─────────────────────────────────────────────────────────────┘
```

**Quy trình chi tiết:**

1. HTML sinh một `nonce` ngẫu nhiên mỗi lần tải trang: `Date.now().toString(36) + Math.random().toString(36).slice(2)`
2. Gọi `GET /api/load-scripts?nonce=xxx` → Server đọc file JS, XOR-encrypt nội dung bằng nonce
3. Client XOR-decrypt lại bằng cùng nonce → khôi phục mã nguồn gốc
4. Tạo `Blob` → `URL.createObjectURL()` → Chèn `<script>` với `src=blob:...`
5. Scripts thực thi từ Blob URL → **Sources tab** hiển thị `blob:http://.../<uuid>` thay vì tên file

**Kết quả:**

| Phương pháp tấn công   | Kết quả                                                 |
| ---------------------- | ------------------------------------------------------- |
| View Source (Ctrl+U)   | Chỉ thấy HTML + inline loader, **không** thấy JS source |
| Gõ URL trực tiếp       | 403 Forbidden                                           |
| Sources tab (DevTools) | Hiển thị `blob:http://...<uuid>`, không phải tên file   |
| Save Page As           | Chỉ lưu HTML, không lưu được Blob scripts               |
| curl / wget            | Chỉ nhận HTML hoặc 403 cho file JS                      |

### 7.4.3. Mã hóa lưu lượng API (API Traffic Encryption)

Tất cả giao tiếp REST API giữa client và server được **mã hóa bằng XOR cipher** với khóa ngẫu nhiên sinh mỗi lần server khởi động:

```
┌──────────────────────────────────────────────────────────────────┐
│  Luồng API Request/Response                                      │
│                                                                  │
│  [1] Server khởi động:                                           │
│      API_CIPHER_KEY = crypto.randomBytes(32).toString('hex')     │
│                                                                  │
│  [2] Client tải key một lần:                                     │
│      GET /api/cipher-key → "a1b2c3d4..."                         │
│                                                                  │
│  [3] Mỗi API call:                                               │
│      Client: { _enc: XOR(requestBody, key) }  ──► Server         │
│      Server: giải mã → xử lý → { _enc: XOR(response, key) }     │
│      Client: giải mã _enc → JSON gốc                            │
└──────────────────────────────────────────────────────────────────┘
```

**Server-side (Middleware pattern):**

```javascript
// Response Encryption: override res.json()
app.use("/api", (req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (data) => {
    const plain = JSON.stringify(data);
    const encrypted = xorCipher(plain, API_CIPHER_KEY);
    originalJson({ _enc: encrypted });
  };
  next();
});

// Request Decryption: unwrap _enc before handlers see req.body
app.use("/api", (req, res, next) => {
  if (req.body && req.body._enc) {
    const decrypted = xorDecipher(req.body._enc, API_CIPHER_KEY);
    req.body = JSON.parse(decrypted);
  }
  next();
});
```

**Client-side (`secureFetch` wrapper):**

```javascript
async function secureFetch(url, options = {}) {
  await _ensureCipherKey(); // Lấy key từ /api/cipher-key (một lần)
  // Mã hóa request body
  if (opts.body)
    opts.body = JSON.stringify({ _enc: _xorCipher(opts.body, key) });
  const response = await fetch(url, opts);
  // Giải mã response
  const envelope = await response.json();
  const plain = _xorDecipher(envelope._enc, key);
  return new Response(plain, { status: response.status });
}
```

**Kết quả khi kiểm tra Network tab:**

```
// Thay vì thấy:
{ "username": "thinh", "friends": [...] }

// Network tab chỉ hiển thị:
{ "_enc": "SxUDFhMLQBNYR3kPFVFcWl0UF1xTXVxHGw==" }
```

### 7.4.4. XOR Cipher – Thuật toán mã hóa đối xứng

SecChatApp sử dụng **XOR Cipher** cho việc mã hóa API traffic và script loading:

```
Encrypt: ciphertext[i] = plaintext[i] XOR key[i % keyLength]
Decrypt: plaintext[i]  = ciphertext[i] XOR key[i % keyLength]
```

| Đặc điểm        | Giá trị                                           |
| --------------- | ------------------------------------------------- |
| Loại cipher     | Đối xứng (Symmetric), Stream cipher               |
| Chiều dài khóa  | 64 hex chars = 256-bit (API key), dynamic (nonce) |
| Encoding output | Base64                                            |
| Tính chất       | XOR(XOR(P, K), K) = P → giải mã = mã hóa lại      |
| Ưu điểm         | Nhanh, đơn giản, phù hợp cho obfuscation layer    |
| Hạn chế         | Không an toàn bằng AES-GCM cho mục đích mật mã    |

> **Lưu ý quan trọng:** XOR cipher ở đây đóng vai trò **lớp che giấu (obfuscation)** trong chiến lược Defense-in-Depth, không thay thế cho mã hóa E2E RSA-OAEP. Tin nhắn vẫn được RSA-OAEP mã hóa đầu cuối — XOR chỉ thêm một lớp bảo vệ cho API traffic.

### 7.4.5. Tổng hợp các lớp bảo vệ mã nguồn

```
┌─────────────────────────────────────────────────────────┐
│              CÁC LỚP BẢO VỆ MÃ NGUỒN                   │
│                                                         │
│  Lớp 1: DevTools Guard (devtools-guard.js)              │
│         → Chặn phím tắt, phát hiện DevTools             │
│                                                         │
│  Lớp 2: Server Middleware                               │
│         → Chặn truy cập trực tiếp file .js (403)        │
│                                                         │
│  Lớp 3: Encrypted Script Loading                        │
│         → Tải JS qua API mã hóa, thực thi từ Blob URL  │
│                                                         │
│  Lớp 4: API Traffic Encryption                          │
│         → Mọi request/response API đều mã hóa XOR      │
│         → Network tab chỉ hiển thị { _enc: "..." }      │
│                                                         │
│  Lớp 5: E2E Encryption (RSA-OAEP)                      │
│         → Tin nhắn luôn mã hóa đầu cuối dù có vượt     │
│            qua tất cả các lớp trên                      │
└─────────────────────────────────────────────────────────┘
```

---

# 🔥 CHAPTER 8: FIREWALL, IDS/IPS

## 8.1. Kiến trúc mạng SecChatApp

Mặc dù SecChatApp là ứng dụng web (không tự triển khai firewall), kiến trúc của nó có các đặc điểm liên quan đến bảo mật mạng:

### 8.1.1. Minimal Network Exposure

| Port/Protocol | Mục đích        | Ghi chú                    |
| ------------- | --------------- | -------------------------- |
| HTTP :3000    | Web + WebSocket | Duy nhất port exposed      |
| Named Pipes   | SQL Server      | Local only, không qua mạng |

### 8.1.2. Socket.io Authentication as Intrusion Prevention

Socket.io middleware hoạt động như một **gatekeeper** kiểu IPS:

```javascript
io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication required"));
  const session = await db.getSessionByToken(token);
  if (session) {
    socket.username = session.Username;
    next(); // ✅ Cho phép kết nối
  } else {
    next(new Error("Authentication required")); // ❌ Chặn kết nối
  }
});
```

- Mọi kết nối WebSocket **phải có token hợp lệ** trước khi được xử lý
- Kết nối không xác thực bị **từ chối ngay lập tức** (fail-closed)

### 8.1.3. Zero-Knowledge Architecture as Defense

Ngay cả khi kẻ tấn công vượt qua firewall và truy cập được server:

```
Kẻ tấn công thấy trong DB:
┌───────────────────────────────────────────────────────┐
│ FromUsername: thinh                                    │
│ ToUsername: nguyenvuonghoantinh                        │
│ EncryptedMessage: nK7f89+a3BmKx...  (Base64 gibberish) │
│ Signature: j2Kp8sW...               (Base64 gibberish) │
│ SentAt: 2026-03-10 18:02:02                           │
└───────────────────────────────────────────────────────┘
→ Biết AI gửi cho AI, KHI NÀO – nhưng KHÔNG biết NỘI DUNG
```

---

# 🧅 CHAPTER 9: SECURE SOCKET LAYERS (SSL/TLS)

## 9.1. Kiến trúc bảo mật tầng giao vận

### 9.1.1. E2E Encryption vs Transport Encryption

SecChatApp sử dụng mã hóa **Application Layer** (E2E) chứ không chỉ dựa vào TLS:

```
Mô hình chỉ dùng TLS (Messenger thường):
  Client ──TLS──► Server (đọc được plaintext) ──TLS──► Client

Mô hình SecChatApp (E2E + TLS):
  Client ──E2E encrypt──► Server (CHỈ thấy ciphertext) ──relay──► Client ──E2E decrypt
```

**E2E mạnh hơn TLS ở chỗ:** Ngay cả khi TLS bị phá (ví dụ bởi quản trị mạng dùng MITM proxy), nội dung tin nhắn vẫn được RSA-OAEP bảo vệ.

### 9.1.2. WebSocket Security

Socket.io trong SecChatApp:

- **Authenticated connection**: Token bắt buộc khi handshake
- **Message relay only**: Server chuyển tiếp ciphertext, không xử lý nội dung
- **Sender public key forwarding**: Gửi kèm `senderPublicKey` để người nhận xác minh chữ ký real-time

```javascript
if (recipient) {
  io.to(data.to).emit("private-message", {
    from: socket.id,
    fromUsername: senderName,
    encryptedMessage: data.encryptedMessage, // Ciphertext, server không đọc
    signature: data.signature, // Chữ ký số
    senderPublicKey: sender.publicKey, // Để recipient verify
  });
}
```

### 9.1.3. Key Format và Export/Import

Khóa được serialize theo 2 format:

| Format            | Sử dụng            | Mục đích                                   |
| ----------------- | ------------------ | ------------------------------------------ |
| **SPKI (Base64)** | Chia sẻ qua server | Public key cho mã hóa/xác minh             |
| **JWK (JSON)**    | localStorage       | Lưu trữ đầy đủ key pair (public + private) |

```javascript
// Export public key (SPKI) để chia sẻ
async function exportPublicKey(key) {
  const exported = await crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

// Export private key (JWK) để lưu local
async function exportPrivateKey(key) {
  return await crypto.subtle.exportKey("jwk", key);
}
```

---

# ⚖ CHAPTER 10: LEGAL & ETHICAL ASPECTS

## 10.1. Quyền riêng tư (Privacy)

SecChatApp thiết kế theo nguyên tắc **Privacy by Design**:

| Nguyên tắc             | Triển khai                                                                          |
| ---------------------- | ----------------------------------------------------------------------------------- |
| **Data minimization**  | Chỉ thu thập username và password hash; không yêu cầu email, SĐT, thông tin cá nhân |
| **Zero-knowledge**     | Server không có khả năng đọc nội dung tin nhắn                                      |
| **User control**       | Người dùng có thể đăng xuất, key bị xóa khỏi bộ nhớ                                 |
| **Transparency**       | Hiển thị rõ ràng trạng thái mã hóa (🔐, ✓, ⚠) cho người dùng                        |
| **Purpose limitation** | Mật khẩu chỉ dùng cho xác thực; public key chỉ dùng cho mã hóa                      |

## 10.2. Đạo đức thông tin

### 10.2.1. Metadata Awareness

Dù nội dung tin nhắn được mã hóa, **metadata** vẫn tồn tại:

- **Ai** gửi cho **ai** (`FromUsername`, `ToUsername`)
- **Khi nào** (`SentAt`)
- **Bao nhiêu** tin nhắn (count)

→ Đây là giới hạn đạo đức và kỹ thuật: SecChatApp minh bạch về việc metadata không được mã hóa.

### 10.2.2. E2E Encryption và pháp luật

- E2E encryption bảo vệ quyền riêng tư người dùng (Điều 21, Hiến pháp Việt Nam 2013)
- Trong trường hợp yêu cầu hợp pháp từ cơ quan chức năng, server chỉ có thể cung cấp **metadata** và **ciphertext** – không thể cung cấp nội dung tin nhắn

---

# 📊 TỔNG KẾT: Bảng ánh xạ tính năng bảo mật

| #   | Tính năng bảo mật                           | Chapter liên quan       | File triển khai                                                        |
| --- | ------------------------------------------- | ----------------------- | ---------------------------------------------------------------------- |
| 1   | Mã hóa RSA-OAEP 2048-bit (E2E Encryption)   | Ch.2 Cryptography       | `crypto.js` → `encryptMessage()`, `decryptMessage()`                   |
| 2   | Chữ ký số RSASSA-PKCS1-v1_5                 | Ch.2 Cryptography       | `crypto.js` → `signMessage()`, `verifySignature()`                     |
| 3   | Hash mật khẩu scrypt + salt                 | Ch.2 Cryptography       | `server.js` → `hashPassword()`                                         |
| 4   | CSPRNG (randomBytes)                        | Ch.2 Cryptography       | `server.js` → `generateToken()`, salt generation                       |
| 5   | SHA-256 (trong RSA-OAEP & RSASSA)           | Ch.2 Cryptography       | `crypto.js` → algorithm config                                         |
| 6   | Token-based session management              | Ch.3 Access Control     | `server.js` → `apiHeaders()`, `getSessionByToken()`                    |
| 7   | Socket.io middleware auth                   | Ch.3 Access Control     | `server.js` → `io.use()`                                               |
| 8   | `timingSafeEqual()` chống timing attack     | Ch.3 Access Control     | `server.js` → login flow                                               |
| 9   | Parameterized SQL queries                   | Ch.3, Ch.7              | `db.js` → mọi function                                                 |
| 10  | Input validation (length, required)         | Ch.7 Software Security  | `server.js` → mọi endpoint                                             |
| 11  | XSS prevention (`textContent`)              | Ch.4 Malicious Code     | `app.js` → rendering                                                   |
| 12  | Zero external crypto dependencies           | Ch.4 Malicious Code     | `crypto.js` → Web Crypto API only                                      |
| 13  | Named Pipes (local DB only)                 | Ch.5 DoS, Ch.8 Firewall | `db.js` → connection string                                            |
| 14  | EncryptedForSender (sender reads own msgs)  | Ch.2 Cryptography       | `app.js`, `db.js`, `server.js`                                         |
| 15  | Key persistence (JWK in localStorage)       | Ch.2 Key Management     | `app.js` → `startChat()`                                               |
| 16  | Zero-knowledge server architecture          | Ch.1 InfoSec, Ch.9 SSL  | `server.js` → relay only                                               |
| 17  | Privacy by Design                           | Ch.10 Legal & Ethics    | Toàn bộ kiến trúc                                                      |
| 18  | JavaScript memory safety                    | Ch.6 Buffer Overflow    | Runtime: V8 Engine                                                     |
| 19  | Chống truy cập DevTools (Source Protection) | Ch.7 Software Security  | `devtools-guard.js` → chặn F12, detect DevTools                        |
| 20  | Chặn truy cập trực tiếp file JS (403)       | Ch.7 Software Security  | `server.js` → middleware PROTECTED_SCRIPTS                             |
| 21  | Encrypted Script Loading (Blob URL)         | Ch.7 Software Security  | `server.js` → `/api/load-scripts`, `index.html` loader                 |
| 22  | API Traffic Encryption (XOR Cipher)         | Ch.7, Ch.2 Cryptography | `server.js` middleware + `app.js` → `secureFetch()`                    |
| 23  | HTTP Security Headers                       | Ch.4, Ch.7              | `server.js` → X-Frame-Options, nosniff, Referrer-Policy                |
| 24  | Rate Limiting (brute-force protection)      | Ch.5 DoS, Ch.3 Access   | `server.js` → `rateLimit()` on login/register                          |
| 25  | Server-side HTML Sanitization               | Ch.4 XSS, Ch.7          | `server.js` → `sanitizeHtml()` escape `<>"'&`                          |
| 26  | Username format whitelist                   | Ch.4 XSS, Ch.7          | `server.js` + `app.js` → `/^[a-zA-Z0-9_]+$/`                           |
| 27  | Message size limit (50KB)                   | Ch.5 DoS                | `server.js` → `encryptedMessage.length > 51200`                        |
| 28  | Encrypted Key Backup (AES-GCM + PBKDF2)     | Ch.2 Key Management     | `crypto.js` → `encryptKeysWithPassword()`, `decryptKeysWithPassword()` |
| 29  | Đồng bộ khóa đa trình duyệt (Cross-Browser) | Ch.2 Key Management     | `app.js` → `startChat()`, `server.js` → `/api/backup-keys`             |
| 30  | Auto Schema Migration (startup migration)   | Ch.7 Software Security  | `server.js` → `db.getPool().then(async pool => ALTER TABLE ...)`       |

---

# 📁 CẤU TRÚC DỰ ÁN

```
SecChatApp/
├── server.js          # Express + Socket.io server, REST API, auth, source protection, auto-migration
├── db.js              # SQL Server connection (Named Pipes), CRUD + key backup operations
├── database.sql       # SQL setup script (tạo DB + tables từ đầu, chạy 1 lần trong SSMS)
├── package.json       # Dependencies: express, socket.io, mssql, msnodesqlv8
├── public/
│   ├── index.html         # UI + inline script loader (Blob URL bootstrap)
│   ├── app.js             # Main app logic, secureFetch(), E2E encryption, key backup/restore
│   ├── crypto.js          # Cryptographic module (Web Crypto API + AES-GCM key backup)
│   ├── devtools-guard.js  # Bảo vệ mã nguồn – chống mở DevTools
│   └── style.css          # Messenger-like dark theme UI
└── test/
    ├── test.js            # Socket.io server unit tests
    ├── test-protection.js # Security layer tests (headers, rate limit, JS access)
    └── test-key-backup.js # Cross-browser key sync integration tests (Playwright)
```

# 🗄️ DATABASE SCHEMA (SQL Server)

```sql
-- Bảng người dùng: lưu hash password + public key
CREATE TABLE Users (
    Id           INT IDENTITY PRIMARY KEY,
    Username     NVARCHAR(20) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(128) NOT NULL,         -- scrypt hash
    Salt         NVARCHAR(32) NOT NULL,           -- 128-bit random
    PublicKey    NVARCHAR(MAX),                   -- JSON {encryption, signing}
    EncryptedKeys NVARCHAR(MAX),                  -- AES-GCM encrypted JWK (cross-browser backup)
    CreatedAt    DATETIME2 DEFAULT GETDATE()
);

-- Bảng phiên: token-based sessions
CREATE TABLE Sessions (
    Id        INT IDENTITY PRIMARY KEY,
    Token     NVARCHAR(64) UNIQUE NOT NULL,       -- 256-bit random
    Username  NVARCHAR(20) NOT NULL,
    CreatedAt DATETIME2 DEFAULT GETDATE()
);

-- Bảng tin nhắn: chỉ lưu CIPHERTEXT
CREATE TABLE Messages (
    Id                 INT IDENTITY PRIMARY KEY,
    FromUsername       NVARCHAR(20) NOT NULL,
    ToUsername         NVARCHAR(20) NOT NULL,
    EncryptedMessage   NVARCHAR(MAX) NOT NULL,    -- RSA-OAEP ciphertext (for recipient)
    EncryptedForSender NVARCHAR(MAX),             -- RSA-OAEP ciphertext (for sender)
    Signature          NVARCHAR(MAX),             -- RSASSA-PKCS1-v1_5 signature
    SentAt             DATETIME2 DEFAULT GETDATE()
);

-- Bảng lời mời kết bạn
CREATE TABLE FriendRequests (
    Id           INT IDENTITY PRIMARY KEY,
    FromUsername NVARCHAR(20) NOT NULL,
    ToUsername   NVARCHAR(20) NOT NULL,
    Status       NVARCHAR(10) DEFAULT 'pending',  -- pending/accepted/rejected
    CreatedAt    DATETIME2 DEFAULT GETDATE()
);

-- Bảng bạn bè
CREATE TABLE Friends (
    Id        INT IDENTITY PRIMARY KEY,
    Username1 NVARCHAR(20) NOT NULL,
    Username2 NVARCHAR(20) NOT NULL,
    CreatedAt DATETIME2 DEFAULT GETDATE()
);
```
