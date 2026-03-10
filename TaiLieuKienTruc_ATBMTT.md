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
└──────────────────────────┬──────────────────────────────┘
                           │
┌─ Phục hồi ──────────────▼──────────────────────────────┐
│ Khi F5 / reload / đăng nhập lại:                        │
│   1. Đọc JWK từ localStorage                            │
│   2. Import lại thành CryptoKey objects                  │
│   3. Nếu thất bại → sinh key mới + lưu lại             │
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

### 2.6.2. EncryptedForSender – Mã hóa bản sao cho người gửi

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

Mặc dù XSS không phải malware truyền thống, đây là vector tấn công nguy hiểm cho ứng dụng web:

SecChatApp sử dụng DOM API thay vì `innerHTML` ở hầu hết các nơi:

```javascript
// Sử dụng textContent (safe) thay vì innerHTML (unsafe)
nameEl.textContent = person.username;
subEl.textContent = preview;
textEl.textContent = msg.text;
```

`textContent` tự động escape HTML entities, ngăn chặn XSS qua nội dung tin nhắn.

---

# 😈 CHAPTER 5: DENIAL OF SERVICE (DoS)

## 5.1. Các biện pháp chống DoS trong SecChatApp

### 5.1.1. Input Validation & Rate Limiting implicimt

| Biện pháp             | Code                                                                        |
| --------------------- | --------------------------------------------------------------------------- |
| Username length limit | `trimmed.length < 3 \|\| trimmed.length > 20`                               |
| Password minimum      | `password.length < 6`                                                       |
| Search debounce       | `setTimeout(doSearch, 300)` — client-side throttle                          |
| Message limit         | `getMessages(user1, user2, limit = 50)` — giới hạn 50 tin nhắn mỗi lần load |
| Search result limit   | `LIKE @q` với input giới hạn 20 ký tự                                       |

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
// Registration
if (!username || !password) return res.status(400).json({ error: "..." });
if (trimmed.length < 3 || trimmed.length > 20)
  return res.status(400).json({ error: "..." });
if (password.length < 6) return res.status(400).json({ error: "..." });

// Send message
if (!toUsername || !encryptedMessage)
  return res.status(400).json({ error: "Missing fields" });

// Friend request
if (!toUsername) return res.status(400).json({ error: "toUsername required" });
if (toUsername === session.Username)
  return res.status(400).json({ error: "Cannot add yourself" });
```

### 7.1.2. Phòng thủ lập trình (Defensive Programming)

| Kỹ thuật                         | Ví dụ trong SecChatApp                                      |
| -------------------------------- | ----------------------------------------------------------- |
| **Fail safely**                  | `result.recordset[0] \|\| null` – trả về null thay vì crash |
| **Check return values**          | `if (!res.ok) return;` – kiểm tra mọi HTTP response         |
| **Parameterized queries**        | Tất cả SQL queries dùng `.input()`                          |
| **Error handling**               | `try/catch` around mọi crypto operation và fetch call       |
| **Principle of least privilege** | Socket chỉ nhận events đã đăng ký                           |

### 7.1.3. Tách biệt Client và Server

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

| #   | Tính năng bảo mật                          | Chapter liên quan       | File triển khai                                      |
| --- | ------------------------------------------ | ----------------------- | ---------------------------------------------------- |
| 1   | Mã hóa RSA-OAEP 2048-bit (E2E Encryption)  | Ch.2 Cryptography       | `crypto.js` → `encryptMessage()`, `decryptMessage()` |
| 2   | Chữ ký số RSASSA-PKCS1-v1_5                | Ch.2 Cryptography       | `crypto.js` → `signMessage()`, `verifySignature()`   |
| 3   | Hash mật khẩu scrypt + salt                | Ch.2 Cryptography       | `server.js` → `hashPassword()`                       |
| 4   | CSPRNG (randomBytes)                       | Ch.2 Cryptography       | `server.js` → `generateToken()`, salt generation     |
| 5   | SHA-256 (trong RSA-OAEP & RSASSA)          | Ch.2 Cryptography       | `crypto.js` → algorithm config                       |
| 6   | Token-based session management             | Ch.3 Access Control     | `server.js` → `apiHeaders()`, `getSessionByToken()`  |
| 7   | Socket.io middleware auth                  | Ch.3 Access Control     | `server.js` → `io.use()`                             |
| 8   | `timingSafeEqual()` chống timing attack    | Ch.3 Access Control     | `server.js` → login flow                             |
| 9   | Parameterized SQL queries                  | Ch.3, Ch.7              | `db.js` → mọi function                               |
| 10  | Input validation (length, required)        | Ch.7 Software Security  | `server.js` → mọi endpoint                           |
| 11  | XSS prevention (`textContent`)             | Ch.4 Malicious Code     | `app.js` → rendering                                 |
| 12  | Zero external crypto dependencies          | Ch.4 Malicious Code     | `crypto.js` → Web Crypto API only                    |
| 13  | Named Pipes (local DB only)                | Ch.5 DoS, Ch.8 Firewall | `db.js` → connection string                          |
| 14  | EncryptedForSender (sender reads own msgs) | Ch.2 Cryptography       | `app.js`, `db.js`, `server.js`                       |
| 15  | Key persistence (JWK in localStorage)      | Ch.2 Key Management     | `app.js` → `startChat()`                             |
| 16  | Zero-knowledge server architecture         | Ch.1 InfoSec, Ch.9 SSL  | `server.js` → relay only                             |
| 17  | Privacy by Design                          | Ch.10 Legal & Ethics    | Toàn bộ kiến trúc                                    |
| 18  | JavaScript memory safety                   | Ch.6 Buffer Overflow    | Runtime: V8 Engine                                   |

---

# 📁 CẤU TRÚC DỰ ÁN

```
SecChatApp/
├── server.js          # Express + Socket.io server, REST API, auth
├── db.js              # SQL Server connection (Named Pipes), CRUD operations
├── package.json       # Dependencies: express, socket.io, mssql, msnodesqlv8
├── public/
│   ├── index.html     # UI: Auth screen + Chat screen
│   ├── app.js         # Main application logic, E2E encryption flow
│   ├── crypto.js      # Cryptographic module (Web Crypto API)
│   └── style.css      # Messenger-like dark theme UI
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
