# API Testing Examples

Complete examples for testing all API endpoints.

## 🔐 Authentication

### 1. Register New User

**Request:**
```http
POST http://localhost:5000/api/auth/register
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Alice@123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "657abc123...",
      "username": "alice",
      "email": "alice@example.com",
      "publicKey": null,
      "isOnline": false,
      "createdAt": "2024-12-01T..."
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### 2. Login

**Request:**
```http
POST http://localhost:5000/api/auth/login
Content-Type: application/json

{
  "email": "alice@example.com",
  "password": "Alice@123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "657abc123...",
      "username": "alice",
      "email": "alice@example.com",
      "publicKey": null,
      "isOnline": true
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### 3. Get Current User Profile

**Request:**
```http
GET http://localhost:5000/api/auth/me
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "657abc123...",
      "username": "alice",
      "email": "alice@example.com",
      "publicKey": null,
      "isOnline": true,
      "lastSeen": "2024-12-01T..."
    }
  }
}
```

### 4. Update Public Key

**Request:**
```http
PUT http://localhost:5000/api/auth/public-key
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "Public key updated successfully",
  "data": {
    "user": {
      "id": "657abc123...",
      "username": "alice",
      "publicKey": "-----BEGIN PUBLIC KEY-----..."
    }
  }
}
```

### 5. Get User by ID

**Request:**
```http
GET http://localhost:5000/api/auth/user/657abc123...
Authorization: Bearer YOUR_JWT_TOKEN
```

### 6. Search Users

**Request:**
```http
GET http://localhost:5000/api/auth/users/search?query=alice
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "657abc123...",
        "username": "alice",
        "email": "alice@example.com",
        "publicKey": "-----BEGIN PUBLIC KEY-----...",
        "isOnline": true
      }
    ]
  }
}
```

### 7. Logout

**Request:**
```http
POST http://localhost:5000/api/auth/logout
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

## 💬 Messages

### 1. Send Encrypted Message

**Request:**
```http
POST http://localhost:5000/api/messages/send
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "recipientId": "657def456...",
  "ciphertext": "U2FsdGVkX1+QzJJWgO3qMZr...",
  "iv": "aWR1aDh1aWRoM2loZA==",
  "tag": "c2RzZGZzZGZzZGY=",
  "seq": 1,
  "signature": "MEUCIQDKx...",
  "messageType": "text"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Message sent successfully",
  "data": {
    "message": {
      "_id": "657ghi789...",
      "sender": {
        "_id": "657abc123...",
        "username": "alice",
        "email": "alice@example.com"
      },
      "recipient": {
        "_id": "657def456...",
        "username": "bob",
        "email": "bob@example.com"
      },
      "ciphertext": "U2FsdGVkX1+QzJJWgO3qMZr...",
      "iv": "aWR1aDh1aWRoM2loZA==",
      "tag": "c2RzZGZzZGZzZGY=",
      "seq": 1,
      "messageType": "text",
      "delivered": false,
      "read": false,
      "createdAt": "2024-12-01T..."
    }
  }
}
```

### 2. Get All Conversations

**Request:**
```http
GET http://localhost:5000/api/messages/conversations
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "conversations": [
      {
        "partner": {
          "_id": "657def456...",
          "username": "bob",
          "email": "bob@example.com",
          "isOnline": true
        },
        "lastMessage": {
          "_id": "657ghi789...",
          "ciphertext": "U2FsdGVkX1+...",
          "createdAt": "2024-12-01T..."
        },
        "unreadCount": 3
      }
    ]
  }
}
```

### 3. Get Conversation with Specific User

**Request:**
```http
GET http://localhost:5000/api/messages/conversation/657def456...?limit=50&skip=0
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "messages": [
      {
        "_id": "657ghi789...",
        "sender": {...},
        "recipient": {...},
        "ciphertext": "U2FsdGVkX1+...",
        "iv": "aWR1aDh1aWRoM2loZA==",
        "tag": "c2RzZGZzZGZzZGY=",
        "seq": 1,
        "delivered": true,
        "read": true,
        "createdAt": "2024-12-01T..."
      }
    ],
    "count": 1
  }
}
```

### 4. Mark Message as Delivered

**Request:**
```http
PATCH http://localhost:5000/api/messages/657ghi789.../delivered
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "message": "Message marked as delivered"
}
```

### 5. Mark Message as Read

**Request:**
```http
PATCH http://localhost:5000/api/messages/657ghi789.../read
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "message": "Message marked as read"
}
```

### 6. Delete Message

**Request:**
```http
DELETE http://localhost:5000/api/messages/657ghi789...
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "message": "Message deleted successfully"
}
```

## 📁 File Operations

### 1. Upload Encrypted File Chunk

**Request:**
```http
POST http://localhost:5000/api/files/upload-chunk
Authorization: Bearer YOUR_JWT_TOKEN
Content-Type: application/json

{
  "messageId": "657ghi789...",
  "chunkNumber": 0,
  "totalChunks": 3,
  "encryptedData": "U2FsdGVkX1+QzJJWgO3qMZr...",
  "iv": "aWR1aDh1aWRoM2loZA==",
  "tag": "c2RzZGZzZGZzZGY=",
  "size": 1024000,
  "hash": "sha256:abc123..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "File chunk uploaded successfully",
  "data": {
    "chunkId": "657jkl012...",
    "chunkNumber": 0,
    "totalChunks": 3,
    "isComplete": false
  }
}
```

### 2. Download File Chunks

**Request:**
```http
GET http://localhost:5000/api/files/download/657ghi789...
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "messageId": "657ghi789...",
    "fileMetadata": {
      "fileName": "document.pdf",
      "fileSize": 3072000,
      "mimeType": "application/pdf"
    },
    "chunks": [
      {
        "chunkNumber": 0,
        "encryptedData": "U2FsdGVkX1+...",
        "iv": "aWR1aDh1aWRoM2loZA==",
        "tag": "c2RzZGZzZGZzZGY=",
        "size": 1024000,
        "hash": "sha256:abc123..."
      },
      {
        "chunkNumber": 1,
        "encryptedData": "U2FsdGVkX1+...",
        "iv": "bmV3aXZoZXJl",
        "tag": "bmV3dGFnZGF0YQ==",
        "size": 1024000,
        "hash": "sha256:def456..."
      },
      {
        "chunkNumber": 2,
        "encryptedData": "U2FsdGVkX1+...",
        "iv": "bGFzdGl2aGVyZQ==",
        "tag": "bGFzdHRhZ2RhdGE=",
        "size": 1024000,
        "hash": "sha256:ghi789..."
      }
    ]
  }
}
```

### 3. Get Upload Progress

**Request:**
```http
GET http://localhost:5000/api/files/progress/657ghi789...
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "messageId": "657ghi789...",
    "totalChunks": 3,
    "uploadedChunks": 2,
    "isComplete": false,
    "percentage": 67
  }
}
```

### 4. Delete File Chunks

**Request:**
```http
DELETE http://localhost:5000/api/files/657ghi789...
Authorization: Bearer YOUR_JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "message": "File chunks deleted successfully",
  "data": {
    "deletedCount": 3
  }
}
```

## 🔌 Socket.io Examples

### JavaScript/TypeScript Client

```javascript
import { io } from 'socket.io-client';

// Connect with authentication
const socket = io('http://localhost:5000', {
  auth: {
    token: 'YOUR_JWT_TOKEN'
  }
});

// Connection events
socket.on('connect', () => {
  console.log('✅ Connected to server');
  console.log('Socket ID:', socket.id);
});

socket.on('disconnect', () => {
  console.log('❌ Disconnected from server');
});

// User presence events
socket.on('user:online', (data) => {
  console.log(`👋 ${data.username} is now online`);
});

socket.on('user:offline', (data) => {
  console.log(`👋 ${data.username} is now offline`);
  console.log(`Last seen: ${data.lastSeen}`);
});

// Key exchange
socket.emit('key-exchange:send', {
  recipientId: 'USER_ID',
  publicKey: '-----BEGIN PUBLIC KEY-----...',
  signature: 'SIGNATURE_DATA'
});

socket.on('key-exchange:receive', (data) => {
  console.log('🔑 Received public key from:', data.senderUsername);
  console.log('Public Key:', data.publicKey);
  console.log('Signature:', data.signature);
  // Verify signature and store public key
});

socket.on('key-exchange:sent', (data) => {
  console.log('✅ Key exchange sent to:', data.recipientId);
});

// Real-time messaging
socket.emit('message:send', {
  messageId: 'MESSAGE_ID',
  recipientId: 'RECIPIENT_ID'
});

socket.on('message:receive', (data) => {
  console.log('📨 New message received');
  console.log('From:', data.message.sender.username);
  console.log('Ciphertext:', data.message.ciphertext);
  // Decrypt and display message
});

socket.on('message:sent', (data) => {
  console.log('✅ Message sent:', data.messageId);
});

// Typing indicators
socket.emit('typing:start', {
  recipientId: 'RECIPIENT_ID'
});

socket.emit('typing:stop', {
  recipientId: 'RECIPIENT_ID'
});

socket.on('typing:user', (data) => {
  if (data.isTyping) {
    console.log(`✍️ ${data.username} is typing...`);
  } else {
    console.log(`${data.username} stopped typing`);
  }
});

// Message delivery confirmations
socket.emit('message:delivered', {
  messageId: 'MESSAGE_ID',
  senderId: 'SENDER_ID'
});

socket.on('message:delivery-confirmed', (data) => {
  console.log('✅ Message delivered:', data.messageId);
});

// Message read confirmations
socket.emit('message:read', {
  messageId: 'MESSAGE_ID',
  senderId: 'SENDER_ID'
});

socket.on('message:read-confirmed', (data) => {
  console.log('👁️ Message read:', data.messageId);
});

// Error handling
socket.on('key-exchange:error', (data) => {
  console.error('❌ Key exchange error:', data.error);
});

socket.on('message:error', (data) => {
  console.error('❌ Message error:', data.error);
});
```

## 📝 Notes

### Base64 Encoding/Decoding

Encrypted data should be Base64 encoded before sending:

```javascript
// Encrypt data (using client-side crypto library)
const encryptedData = encryptFunction(plaintext, key);

// Encode to Base64
const base64Ciphertext = btoa(String.fromCharCode(...new Uint8Array(encryptedData)));
const base64IV = btoa(String.fromCharCode(...new Uint8Array(iv)));
const base64Tag = btoa(String.fromCharCode(...new Uint8Array(tag)));

// Send to server
await fetch('http://localhost:5000/api/messages/send', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    recipientId,
    ciphertext: base64Ciphertext,
    iv: base64IV,
    tag: base64Tag,
    seq: 1
  })
});
```

### Sequence Numbers

To prevent replay attacks, increment sequence numbers for each message:

```javascript
let messageSeq = 0;

async function sendMessage(recipientId, plaintext) {
  messageSeq++;
  
  const encrypted = await encryptMessage(plaintext);
  
  await sendToServer({
    recipientId,
    ...encrypted,
    seq: messageSeq
  });
}
```

### Rate Limiting

Be aware of rate limits:
- **General API**: 100 requests per 15 minutes
- **Auth endpoints**: 5 attempts per 15 minutes  
- **Messages**: 30 per minute

If you hit rate limits, you'll receive:
```json
{
  "error": "Too many requests from this IP, please try again later."
}
```

---

**Happy Testing! 🚀**

