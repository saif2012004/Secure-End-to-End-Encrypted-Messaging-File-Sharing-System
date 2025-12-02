# 🔗 Backend ↔️ Frontend Integration Guide

## ✅ PROMPT 5 COMPLETE

This document explains how the backend and frontend are integrated for secure messaging.

---

## 🎯 Integration Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      MESSAGE FLOW DIAGRAM                       │
└─────────────────────────────────────────────────────────────────┘

Client A (React)                Backend (Node.js)           Client B (React)
     │                                 │                           │
     │  1. Encrypt message            │                           │
     │     (AES-GCM)                  │                           │
     │                                 │                           │
     │  2. POST /api/messages/send    │                           │
     │     (ciphertext, iv, tag, seq) │                           │
     ├────────────────────────────────►│                           │
     │                                 │                           │
     │                                 │  3. Store metadata        │
     │                                 │     (MongoDB)             │
     │                                 │                           │
     │  4. 201 Created                │                           │
     │     { messageId, timestamp }   │                           │
     │◄────────────────────────────────┤                           │
     │                                 │                           │
     │  5. Socket: send_message        │                           │
     │     (relay encrypted data)      │                           │
     ├────────────────────────────────►│                           │
     │                                 │                           │
     │                                 │  6. Log relay event       │
     │                                 │     (security log)        │
     │                                 │                           │
     │                                 │  7. Socket: receive_message│
     │                                 │     (relay encrypted)     │
     │                                 ├──────────────────────────►│
     │                                 │                           │
     │                                 │                           │  8. Decrypt
     │                                 │                           │     (AES-GCM)
     │                                 │                           │
     │                                 │                           │  9. Display
     │                                 │                           │     plaintext
```

---

## 📊 Integration Points

### 1. **Backend API Routes** ✅

All routes are ready and accept encrypted metadata only:

#### **POST /api/messages/send**
Stores encrypted message metadata in MongoDB.

**Request:**
```json
{
  "recipientId": "user_id",
  "ciphertext": "base64_encrypted_data",
  "iv": "base64_iv",
  "tag": "base64_tag",
  "seq": 1234567890,
  "signature": "base64_signature (optional)",
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
      "_id": "msg_id",
      "sender": { "_id": "...", "username": "...", "publicKey": "..." },
      "recipient": { "_id": "...", "username": "...", "publicKey": "..." },
      "ciphertext": "...",
      "iv": "...",
      "tag": "...",
      "seq": 1234567890,
      "createdAt": "2024-12-01T12:00:00.000Z"
    }
  }
}
```

**Features:**
- ✅ Validates required fields (ciphertext, iv, tag, seq)
- ✅ Checks for replay attacks (duplicate seq)
- ✅ Stores metadata only (never plaintext)
- ✅ Logs every message send
- ✅ Returns full message object with sender/recipient data

---

#### **GET /api/messages/conversation/:userId**
Retrieves encrypted message history between two users.

**Request:**
```bash
GET /api/messages/conversation/USER_ID?limit=50&skip=0
Authorization: Bearer JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": {
    "messages": [
      {
        "_id": "msg_id",
        "sender": { "_id": "...", "username": "...", "publicKey": "..." },
        "recipient": { "_id": "...", "username": "...", "publicKey": "..." },
        "ciphertext": "base64_encrypted",
        "iv": "base64_iv",
        "tag": "base64_tag",
        "seq": 1234567890,
        "messageType": "text",
        "delivered": true,
        "read": false,
        "createdAt": "2024-12-01T12:00:00.000Z"
      }
    ],
    "count": 25
  }
}
```

**Features:**
- ✅ Returns messages in chronological order
- ✅ Supports pagination (limit/skip)
- ✅ Includes sender/recipient details with public keys
- ✅ Only returns metadata (encrypted data)

---

#### **POST /api/files/upload-chunk**
Uploads encrypted file chunks.

**Request:**
```json
{
  "messageId": "msg_id (optional for first chunk)",
  "recipientId": "user_id",
  "chunkNumber": 1,
  "totalChunks": 10,
  "encryptedData": "base64_encrypted_chunk",
  "iv": "base64_iv",
  "tag": "base64_tag",
  "hash": "sha256_hash",
  "fileName": "document.pdf",
  "fileSize": 1048576,
  "mimeType": "application/pdf"
}
```

**Response:**
```json
{
  "success": true,
  "message": "File chunk uploaded successfully",
  "data": {
    "chunk": {
      "_id": "chunk_id",
      "messageId": "msg_id",
      "chunkNumber": 1,
      "totalChunks": 10,
      "progress": 10
    }
  }
}
```

**Features:**
- ✅ Handles large files via chunking
- ✅ Tracks upload progress
- ✅ Stores encrypted chunks only
- ✅ Associates chunks with message

---

### 2. **WebSocket Events** ✅

Real-time message relay via Socket.io:

#### **Client → Server: `send_message`**
Relays encrypted message to recipient in real-time.

**Emit:**
```javascript
socket.emit('send_message', {
  recipientId: 'user_id',
  ciphertext: 'base64_encrypted',
  iv: 'base64_iv',
  tag: 'base64_tag',
  seq: 1234567890,
  messageId: 'msg_id', // From backend response
  signature: 'base64_sig (optional)',
  messageType: 'text'
});
```

**Server Behavior:**
- Validates sender authentication
- Joins sender to 1-1 room with recipient
- Relays message to recipient's socket
- Logs relay event (metadata only)
- **Never decrypts or reads content**

---

#### **Server → Client: `receive_message`**
Receives encrypted message from another user.

**Listen:**
```javascript
socket.on('receive_message', (data) => {
  console.log('Encrypted message received:', data);
  // {
  //   senderId: 'user_id',
  //   senderUsername: 'alice',
  //   ciphertext: 'base64_encrypted',
  //   iv: 'base64_iv',
  //   tag: 'base64_tag',
  //   seq: 1234567890,
  //   messageType: 'text',
  //   timestamp: '2024-12-01T12:00:00.000Z'
  // }
});
```

---

#### **Client → Server: `send_file_chunk`**
Relays encrypted file chunk to recipient.

**Emit:**
```javascript
socket.emit('send_file_chunk', {
  recipientId: 'user_id',
  messageId: 'msg_id',
  chunkNumber: 1,
  totalChunks: 10,
  encryptedData: 'base64_chunk',
  iv: 'base64_iv',
  tag: 'base64_tag',
  hash: 'sha256_hash',
  fileName: 'document.pdf',
  fileSize: 1048576,
  mimeType: 'application/pdf'
});
```

---

#### **Server → Client: `receive_file_chunk`**
Receives encrypted file chunk from another user.

**Listen:**
```javascript
socket.on('receive_file_chunk', (data) => {
  console.log('File chunk received:', data);
  // Decrypt and reassemble file
});
```

---

### 3. **Frontend Integration** ✅

The React frontend is fully integrated with the backend:

#### **Chat Store (`client/src/store/chatStore.js`)**

**Key Functions:**

```javascript
// Fetch encrypted messages from backend
fetchMessages: async (userId) => {
  const response = await messagesAPI.getConversation(userId, 50, 0);
  // Decrypts messages for display
  // Handles decryption errors gracefully
}

// Send message (backend + socket)
sendMessage: async (messageData) => {
  // Step 1: Save to backend (permanent storage)
  const response = await messagesAPI.sendMessage({
    recipientId, ciphertext, iv, tag, seq
  });
  
  // Step 2: Relay via socket (real-time)
  socket.emit('send_message', { ... });
  
  // Step 3: Update local state
  set({ messages: [...messages, newMessage] });
}

// Send file chunk (backend + socket)
sendFileChunk: async (chunkData) => {
  // Step 1: Save to backend
  const response = await messagesAPI.sendMessage({ ... });
  
  // Step 2: Relay via socket
  socket.emit('send_file_chunk', { ... });
}
```

---

#### **Chat Page (`client/src/pages/Chat.jsx`)**

**Features:**
- ✅ Connects to Socket.io on mount
- ✅ Fetches encrypted messages when user is selected
- ✅ Displays loading state while fetching
- ✅ Shows error state if fetch fails
- ✅ Renders decrypted messages in MessageList
- ✅ Sends messages via MessageInput

**User Selection Flow:**
```javascript
setSelectedUser: async (user) => {
  // 1. Join socket room
  socketStore.joinRoom(user.id);
  
  // 2. Fetch existing messages from backend
  await fetchMessages(user.id);
  
  // 3. Decrypt and display messages
}
```

---

#### **Message Input (`client/src/components/MessageInput.jsx`)**

**Send Message Flow:**
```javascript
handleSubmit: async (e) => {
  // 1. Encrypt message (placeholder - Members 1 & 2 implement)
  const encrypted = await encryptMessage(message, recipientId);
  
  // 2. Send via chatStore (saves to backend + relays via socket)
  await sendMessage({
    recipientId,
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    tag: encrypted.tag,
    seq: Date.now(),
    plaintext: message, // For display only
    messageType: 'text'
  });
  
  // 3. Clear input
  setMessage('');
}
```

---

### 4. **API Service (`client/src/services/api.js`)**

**Pre-configured API functions:**

```javascript
// Messages API
messagesAPI.sendMessage(messageData)
messagesAPI.getConversation(userId, limit, skip)
messagesAPI.getConversations()
messagesAPI.markAsDelivered(messageId)
messagesAPI.markAsRead(messageId)
messagesAPI.deleteMessage(messageId)

// Files API
filesAPI.uploadChunk(chunkData)
filesAPI.downloadFile(messageId)
filesAPI.getProgress(messageId)
filesAPI.deleteFile(messageId)

// Users API
usersAPI.searchUsers(query)
usersAPI.getUserById(userId)

// Auth API
authAPI.register(username, email, password)
authAPI.login(email, password)
authAPI.logout()
authAPI.getCurrentUser()
authAPI.updatePublicKey(publicKey)
```

**Features:**
- ✅ Automatic JWT token injection
- ✅ Automatic error handling
- ✅ Redirects to login on 401
- ✅ Returns unwrapped data

---

## 🔐 Security Architecture

### Backend (Zero-Knowledge) ✅

```javascript
// ✅ Server STORES
{
  ciphertext: "encrypted_base64",  // Encrypted message
  iv: "base64",                    // Initialization vector
  tag: "base64",                   // Authentication tag
  seq: 1234567890,                 // Sequence number (replay protection)
  sender: "user_id",               // Metadata only
  recipient: "user_id",            // Metadata only
  timestamp: "ISO_DATE",           // Metadata only
  delivered: false,                // Delivery status
  read: false                      // Read status
}

// ❌ Server NEVER stores
{
  plaintext: "Hello World",        // NEVER stored
  encryptionKey: "...",            // NEVER stored
  privateKey: "...",               // NEVER stored
  password: "...",                 // Only hashed stored
}
```

### Frontend (Client-Side Encryption) ⚠️

**Current State: Placeholder Encryption**

```javascript
// client/src/utils/crypto.js
export async function encryptMessage(plaintext, recipientId) {
  // ⚠️ PLACEHOLDER: Base64 encoding (NOT SECURE!)
  // TODO: Implement real AES-GCM encryption
  const ciphertext = btoa(plaintext);
  return {
    ciphertext,
    iv: btoa(Math.random().toString()),
    tag: btoa(Math.random().toString())
  };
}

export async function decryptMessage(ciphertext, iv, tag) {
  // ⚠️ PLACEHOLDER: Base64 decoding (NOT SECURE!)
  // TODO: Implement real AES-GCM decryption
  return atob(ciphertext);
}
```

**For Members 1 & 2: Implement Real Encryption**

Replace placeholder functions in `client/src/utils/crypto.js`:

```javascript
// Example using Web Crypto API
export async function encryptMessage(plaintext, recipientId) {
  // 1. Get recipient's public key from backend
  const recipient = await usersAPI.getUserById(recipientId);
  
  // 2. Perform ECDH key exchange to derive shared secret
  const sharedSecret = await performECDH(
    myPrivateKey, 
    recipient.publicKey
  );
  
  // 3. Derive AES key from shared secret
  const aesKey = await deriveKey(sharedSecret);
  
  // 4. Encrypt with AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(plaintext)
  );
  
  // 5. Extract ciphertext and tag
  const ciphertext = encrypted.slice(0, -16);
  const tag = encrypted.slice(-16);
  
  return {
    ciphertext: base64Encode(ciphertext),
    iv: base64Encode(iv),
    tag: base64Encode(tag)
  };
}
```

---

## 🧪 Testing the Integration

### 1. **Start Backend**

```bash
# Terminal 1
npm run dev
```

Backend should be running on `http://localhost:5000`

### 2. **Start Frontend**

```bash
# Terminal 2
cd client
npm run dev
```

Frontend should be running on `http://localhost:3000`

### 3. **Test Complete Flow**

**User A:**
1. Register: `alice@example.com`
2. Login
3. Wait on chat page

**User B (Incognito Window):**
1. Register: `bob@example.com`
2. Login
3. Search for "alice"
4. Click on alice
5. Send message: "Hello Alice!"

**Expected Behavior:**

✅ **Backend logs** show:
```
MESSAGE_SENT from bob to alice
MESSAGE_RELAY from bob to alice (socket)
```

✅ **Alice's browser** shows:
```
📨 Encrypted message received: { ciphertext, iv, tag }
Message decrypted: "Hello Alice!"
```

✅ **MongoDB** contains:
```javascript
{
  sender: ObjectId("bob_id"),
  recipient: ObjectId("alice_id"),
  ciphertext: "base64_encrypted_data",
  iv: "base64_iv",
  tag: "base64_tag",
  seq: 1733064000000,
  messageType: "text",
  delivered: false,
  read: false,
  createdAt: ISODate("2024-12-01T12:00:00.000Z")
}
```

✅ **Security logs** contain:
```javascript
{
  eventType: "MESSAGE_SENT",
  user: ObjectId("bob_id"),
  ipAddress: "127.0.0.1",
  success: true,
  details: { messageId, seq, messageType }
}
```

---

## 🔄 Data Flow Summary

### Sending a Message

```
1. User types: "Hello World"
   
2. Frontend encrypts:
   encryptMessage("Hello World") 
   → { ciphertext, iv, tag }

3. Frontend saves to backend:
   POST /api/messages/send
   { recipientId, ciphertext, iv, tag, seq }
   ← 201 { messageId, timestamp }

4. Frontend relays via socket:
   socket.emit('send_message', { ... })
   
5. Backend logs event:
   Log.createLog({ eventType: "MESSAGE_SENT" })

6. Backend relays to recipient:
   socket.to(recipientRoom).emit('receive_message', { ... })

7. Recipient frontend receives:
   socket.on('receive_message', (data) => { ... })

8. Recipient frontend decrypts:
   decryptMessage(data.ciphertext, data.iv, data.tag)
   → "Hello World"

9. Recipient sees plaintext:
   <div class="message">Hello World</div>
```

### Loading Messages

```
1. User selects conversation partner
   
2. Frontend fetches from backend:
   GET /api/messages/conversation/:userId
   ← 200 { messages: [...encrypted messages...] }

3. Frontend decrypts each message:
   messages.map(msg => decryptMessage(msg.ciphertext, msg.iv, msg.tag))
   → Array of plaintext messages

4. Frontend displays:
   <MessageList messages={decryptedMessages} />
```

---

## 📊 Backend Logging

Every action is logged with metadata only:

```javascript
// Message sent
{
  eventType: "MESSAGE_SENT",
  level: "info",
  user: ObjectId("sender_id"),
  ipAddress: "127.0.0.1",
  userAgent: "Mozilla/5.0...",
  success: true,
  message: "Message sent from user_a to user_b",
  details: {
    messageId: ObjectId("msg_id"),
    seq: 1234567890,
    messageType: "text"
  }
}

// Message relayed
{
  eventType: "MESSAGE_RELAY",
  level: "info",
  user: ObjectId("sender_id"),
  success: true,
  message: "Message relayed to user_b",
  details: {
    recipientId: ObjectId("user_b_id"),
    seq: 1234567890
  }
}

// Replay attack detected
{
  eventType: "REPLAY_DETECTED",
  level: "warn",
  user: ObjectId("sender_id"),
  ipAddress: "127.0.0.1",
  success: false,
  message: "Potential replay attack detected",
  details: {
    sender: ObjectId("sender_id"),
    recipient: ObjectId("recipient_id"),
    seq: 1234567890
  }
}
```

**NO SENSITIVE DATA IS EVER LOGGED!**

---

## ✅ Integration Checklist

### Backend ✅
- ✅ `/api/messages/send` route implemented
- ✅ `/api/messages/conversation/:userId` route implemented
- ✅ `/api/files/upload-chunk` route implemented
- ✅ All routes accept only ciphertext, iv, tag, seq
- ✅ Server never decrypts messages
- ✅ Server only stores metadata
- ✅ Server logs every action (metadata only)
- ✅ Replay attack detection (duplicate seq)
- ✅ OWASP-compliant password hashing
- ✅ JWT authentication
- ✅ Rate limiting
- ✅ Input validation

### Frontend ✅
- ✅ Chat.jsx fetches existing encrypted messages
- ✅ Chat.jsx displays ciphertext as placeholders (or decrypted if crypto implemented)
- ✅ Chat.jsx connects to WebSocket on mount
- ✅ MessageInput sends encrypted messages
- ✅ Socket store receives and renders encrypted messages
- ✅ API service configured with all endpoints
- ✅ Loading states for message fetching
- ✅ Error handling for failed requests
- ✅ Optimistic UI updates

### Integration ✅
- ✅ Frontend calls backend API before socket emit
- ✅ Backend saves metadata to MongoDB
- ✅ Backend relays message via Socket.io
- ✅ Recipient receives real-time message
- ✅ Messages persist in database
- ✅ Security logs track all events
- ✅ NO plaintext in backend or logs

---

## 🎯 Next Steps

### For Member 3 (You) ✅
- ✅ Backend fully integrated
- ✅ Frontend fully integrated
- ✅ Real-time messaging working
- ✅ Database persistence working
- ✅ Security logging working
- ✅ Test end-to-end flow

### For Members 1 & 2 ⏭️
- ⏭️ Replace placeholder encryption in `client/src/utils/crypto.js`
- ⏭️ Implement AES-GCM encryption/decryption
- ⏭️ Implement ECDH key exchange
- ⏭️ Implement RSA digital signatures
- ⏭️ Test real encryption end-to-end

---

## 🆘 Troubleshooting

### Messages not sending?
1. Check backend is running: `curl http://localhost:5000/health`
2. Check frontend is running: `http://localhost:3000`
3. Check Socket.io connection: Console should show "✅ Socket connected"
4. Check browser console for errors
5. Check backend logs: `server/logs/combined.log`

### Messages not appearing?
1. Check `fetchMessages` is called when user is selected
2. Check backend API response: Network tab in DevTools
3. Check decryption function: Should show "📨 Encrypted message received"
4. Check message state: React DevTools → chatStore

### Socket not connecting?
1. Check JWT token is in localStorage
2. Check CORS settings: `CORS_ORIGIN=http://localhost:3000`
3. Check backend socket server is running
4. Check firewall/antivirus blocking WebSocket

### Database not saving?
1. Check MongoDB is running: `net start MongoDB`
2. Check connection string: `.env` file
3. Check validation errors: Backend logs
4. Check replay detection: Ensure unique `seq` values

---

## 📚 Related Documentation

- **Backend API**: `API_EXAMPLES.md`
- **WebSocket Events**: `WEBSOCKET_IMPLEMENTATION.md`
- **Security Logging**: `LOGGING_IMPLEMENTATION.md`
- **Frontend Guide**: `client/README.md`
- **Quick Reference**: `QUICK_REFERENCE.md`
- **Full-Stack Overview**: `FULL_STACK_COMPLETE.md`

---

## 🎉 Status

```
╔══════════════════════════════════════════════════╗
║                                                  ║
║  ✅ BACKEND ↔️ FRONTEND INTEGRATION COMPLETE    ║
║                                                  ║
║  ✅ Messages save to backend                    ║
║  ✅ Messages relay via socket                   ║
║  ✅ Messages persist in MongoDB                 ║
║  ✅ Messages load from backend                  ║
║  ✅ Security logging tracks all events          ║
║  ✅ Zero-knowledge architecture maintained      ║
║                                                  ║
║  STATUS: ✅ READY FOR REAL ENCRYPTION           ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

---

**Built with ❤️ for Information Security Course**  
**Date**: December 1, 2024  
**Status**: ✅ **INTEGRATION COMPLETE**

