# WebSocket/Socket.io Implementation Guide

## 🔌 Overview

This document describes the **complete WebSocket implementation** for the secure messaging backend. The server acts as a **relay only** - it does NOT perform any encryption or decryption.

## ⚠️ Important: Zero-Knowledge Architecture

- ✅ Server **RELAYS** encrypted messages (ciphertext only)
- ✅ Server **DOES NOT decrypt** any messages
- ✅ Server **DOES NOT inspect** message contents
- ✅ All cryptography is handled **client-side**
- ✅ Encrypted data is logged as metadata only (no content)

---

## 📁 Files Modified

### 1. `server/sockets/chatSocket.js`
Enhanced WebSocket handler with:
- Room-based 1-1 chat
- Message relay (encrypted)
- File chunk relay (encrypted)
- Comprehensive event logging

### 2. `server/server.js`
Already configured properly:
```javascript
// Initialize Socket.io
const io = initializeSocket(server);

// Make io accessible to route handlers
app.set('io', io);
```

No changes needed!

---

## 🎯 Features Implemented

### ✅ Connection Management
- JWT-based authentication
- User connection/disconnection
- Online/offline status tracking
- Automatic reconnection support

### ✅ Room-Based Chat
- Explicit room joining: `join_room`
- Room leaving: `leave_room`
- Room format: `userId1_userId2` (sorted)
- Targeted message delivery

### ✅ Message Relay
- Event: `send_message`
- Relays: ciphertext, IV, tag, seq
- NO decryption performed
- Delivery confirmation

### ✅ File Chunk Relay
- Event: `send_file_chunk`
- Supports large file transfer
- Chunk-by-chunk relay
- Progress tracking
- NO decryption performed

### ✅ Real-Time Features
- Typing indicators
- Key exchange relay
- Message delivery/read receipts
- User presence

### ✅ Security Logging
- All events logged to MongoDB
- Metadata only (no content)
- Audit trail for compliance

---

## 📡 WebSocket Events Reference

### Client → Server Events

#### 1. Connection
```javascript
const socket = io('http://localhost:5000', {
  auth: {
    token: 'YOUR_JWT_TOKEN'
  }
});
```

#### 2. Join Room (1-1 Chat)
```javascript
socket.emit('join_room', {
  recipientId: 'USER_ID'
});

socket.on('room:joined', (data) => {
  console.log('Joined room:', data.roomName);
  // { roomName: 'userId1_userId2', recipientId, success: true }
});
```

#### 3. Leave Room
```javascript
socket.emit('leave_room', {
  recipientId: 'USER_ID'
});

socket.on('room:left', (data) => {
  console.log('Left room:', data.roomName);
});
```

#### 4. Send Encrypted Message
```javascript
socket.emit('send_message', {
  recipientId: 'RECIPIENT_USER_ID',
  ciphertext: 'BASE64_ENCRYPTED_DATA',    // Encrypted - server doesn't decrypt
  iv: 'BASE64_IV',                        // Initialization vector
  tag: 'BASE64_TAG',                      // Authentication tag
  seq: 1,                                 // Sequence number
  signature: 'SIGNATURE_DATA',            // Optional digital signature
  messageType: 'text'                     // 'text' or 'file'
});

socket.on('message:sent', (data) => {
  console.log('Message sent:', data);
  // { recipientId, seq, success: true, timestamp }
});
```

#### 5. Send Encrypted File Chunk
```javascript
socket.emit('send_file_chunk', {
  recipientId: 'RECIPIENT_USER_ID',
  messageId: 'MESSAGE_ID',
  chunkNumber: 0,                         // 0-indexed
  totalChunks: 5,
  encryptedData: 'BASE64_ENCRYPTED_CHUNK', // Encrypted - server doesn't decrypt
  iv: 'BASE64_IV',
  tag: 'BASE64_TAG',
  hash: 'SHA256_HASH',
  fileName: 'document.pdf',
  fileSize: 5242880,                      // Bytes
  mimeType: 'application/pdf'
});

socket.on('file:chunk-sent', (data) => {
  console.log(`Chunk ${data.chunkNumber + 1}/${data.totalChunks} sent`);
});

socket.on('file:upload-complete', (data) => {
  console.log('All chunks sent!');
});
```

#### 6. Request File Download
```javascript
socket.emit('request_file', {
  senderId: 'SENDER_USER_ID',
  messageId: 'MESSAGE_ID'
});

socket.on('file:request-sent', (data) => {
  console.log('File requested');
});
```

#### 7. Key Exchange
```javascript
socket.emit('key-exchange:send', {
  recipientId: 'RECIPIENT_USER_ID',
  publicKey: '-----BEGIN PUBLIC KEY-----...',
  signature: 'SIGNATURE_DATA'
});

socket.on('key-exchange:sent', (data) => {
  console.log('Key exchanged with:', data.recipientId);
});
```

#### 8. Typing Indicators
```javascript
// Start typing
socket.emit('typing:start', {
  recipientId: 'RECIPIENT_USER_ID'
});

// Stop typing
socket.emit('typing:stop', {
  recipientId: 'RECIPIENT_USER_ID'
});
```

#### 9. Message Status Updates
```javascript
// Mark as delivered
socket.emit('message:delivered', {
  messageId: 'MESSAGE_ID',
  senderId: 'SENDER_USER_ID'
});

// Mark as read
socket.emit('message:read', {
  messageId: 'MESSAGE_ID',
  senderId: 'SENDER_USER_ID'
});
```

---

### Server → Client Events

#### 1. Connection Status
```javascript
socket.on('connect', () => {
  console.log('✅ Connected to server');
  console.log('Socket ID:', socket.id);
});

socket.on('disconnect', () => {
  console.log('❌ Disconnected from server');
});
```

#### 2. Room Events
```javascript
socket.on('room:joined', (data) => {
  // { roomName, recipientId, success }
  console.log('Joined chat room:', data.roomName);
});

socket.on('room:left', (data) => {
  // { roomName, success }
  console.log('Left chat room');
});

socket.on('room:user-ready', (data) => {
  // { userId, username, roomName }
  console.log(`${data.username} is ready to chat`);
});

socket.on('room:error', (data) => {
  console.error('Room error:', data.error);
});
```

#### 3. Receive Encrypted Message
```javascript
socket.on('receive_message', (data) => {
  const {
    senderId,
    senderUsername,
    ciphertext,      // Encrypted - decrypt this client-side
    iv,
    tag,
    seq,
    signature,
    messageType,
    timestamp
  } = data;

  console.log(`📨 New encrypted message from ${senderUsername}`);
  
  // Decrypt message client-side
  const plaintext = decryptMessage(ciphertext, iv, tag);
  console.log('Decrypted:', plaintext);
});
```

#### 4. Receive Encrypted File Chunk
```javascript
socket.on('receive_file_chunk', (data) => {
  const {
    senderId,
    senderUsername,
    messageId,
    chunkNumber,
    totalChunks,
    encryptedData,   // Encrypted - decrypt this client-side
    iv,
    tag,
    hash,
    fileName,
    fileSize,
    mimeType,
    timestamp
  } = data;

  console.log(`📎 File chunk ${chunkNumber + 1}/${totalChunks} from ${senderUsername}`);
  
  // Decrypt chunk client-side
  const decryptedChunk = decryptChunk(encryptedData, iv, tag);
  
  // Store chunk and reassemble when complete
  storeChunk(chunkNumber, decryptedChunk);
  
  if (chunkNumber === totalChunks - 1) {
    const fullFile = reassembleFile();
    console.log('✅ File received and decrypted:', fileName);
  }
});
```

#### 5. File Request
```javascript
socket.on('file:requested', (data) => {
  const { requesterId, requesterUsername, messageId } = data;
  
  console.log(`${requesterUsername} requested file download`);
  
  // Start sending file chunks
  sendFileChunks(requesterId, messageId);
});
```

#### 6. User Presence
```javascript
socket.on('user:online', (data) => {
  console.log(`👋 ${data.username} is now online`);
  // Update UI to show user is online
});

socket.on('user:offline', (data) => {
  console.log(`👋 ${data.username} is now offline`);
  console.log(`Last seen: ${data.lastSeen}`);
  // Update UI to show user is offline
});
```

#### 7. Key Exchange
```javascript
socket.on('key-exchange:receive', (data) => {
  const { senderId, senderUsername, publicKey, signature } = data;
  
  console.log(`🔑 Received public key from ${senderUsername}`);
  
  // Verify signature (client-side)
  if (verifySignature(publicKey, signature)) {
    // Store public key for encryption
    storePublicKey(senderId, publicKey);
  }
});
```

#### 8. Typing Indicators
```javascript
socket.on('typing:user', (data) => {
  const { userId, username, isTyping } = data;
  
  if (isTyping) {
    console.log(`✍️ ${username} is typing...`);
    // Show typing indicator in UI
  } else {
    console.log(`${username} stopped typing`);
    // Hide typing indicator
  }
});
```

#### 9. Delivery Confirmations
```javascript
socket.on('message:delivery-confirmed', (data) => {
  console.log(`✅ Message ${data.messageId} delivered`);
  // Update message status in UI
});

socket.on('message:read-confirmed', (data) => {
  console.log(`👁️ Message ${data.messageId} read`);
  // Update message status in UI
});
```

#### 10. Error Events
```javascript
socket.on('message:error', (data) => {
  console.error('❌ Message error:', data.error);
});

socket.on('file:error', (data) => {
  console.error('❌ File error:', data.error);
});

socket.on('key-exchange:error', (data) => {
  console.error('❌ Key exchange error:', data.error);
});
```

---

## 🔄 Complete Workflow Examples

### Example 1: Sending an Encrypted Message

```javascript
// 1. Connect with JWT
const socket = io('http://localhost:5000', {
  auth: { token: jwtToken }
});

// 2. Join chat room
socket.emit('join_room', { recipientId: 'bob123' });

// 3. Wait for room confirmation
socket.on('room:joined', (data) => {
  console.log('Room joined:', data.roomName);
  
  // 4. Encrypt message client-side
  const plaintext = 'Hello Bob!';
  const { ciphertext, iv, tag } = encryptMessage(plaintext, recipientPublicKey);
  
  // 5. Send encrypted message
  socket.emit('send_message', {
    recipientId: 'bob123',
    ciphertext,
    iv,
    tag,
    seq: 1,
    messageType: 'text'
  });
});

// 6. Wait for confirmation
socket.on('message:sent', (data) => {
  console.log('✅ Message sent at:', data.timestamp);
});

// 7. Receive response
socket.on('receive_message', (data) => {
  // Decrypt response
  const response = decryptMessage(data.ciphertext, data.iv, data.tag);
  console.log('Response:', response);
});
```

### Example 2: Sending an Encrypted File

```javascript
// 1. Connect and join room (same as above)

// 2. Prepare file
const file = document.getElementById('fileInput').files[0];
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

// 3. Send chunks
for (let i = 0; i < totalChunks; i++) {
  const start = i * CHUNK_SIZE;
  const end = Math.min(start + CHUNK_SIZE, file.size);
  const chunk = file.slice(start, end);
  
  // Read chunk
  const arrayBuffer = await chunk.arrayBuffer();
  const uint8Array = new Uint8Array(arrayBuffer);
  
  // Encrypt chunk client-side
  const { encryptedData, iv, tag } = encryptChunk(uint8Array, recipientPublicKey);
  
  // Calculate hash
  const hash = await sha256(encryptedData);
  
  // Send encrypted chunk
  socket.emit('send_file_chunk', {
    recipientId: 'bob123',
    messageId: 'msg123',
    chunkNumber: i,
    totalChunks,
    encryptedData: btoa(String.fromCharCode(...encryptedData)),
    iv: btoa(String.fromCharCode(...iv)),
    tag: btoa(String.fromCharCode(...tag)),
    hash,
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type
  });
  
  // Wait for confirmation
  await new Promise(resolve => {
    socket.once('file:chunk-sent', resolve);
  });
}

// 4. All chunks sent
socket.on('file:upload-complete', (data) => {
  console.log('✅ File uploaded successfully!');
});
```

### Example 3: Receiving and Decrypting a File

```javascript
let fileChunks = [];
let expectedChunks = 0;
let fileName = '';

socket.on('receive_file_chunk', async (data) => {
  const {
    chunkNumber,
    totalChunks,
    encryptedData,
    iv,
    tag,
    fileName: name,
    mimeType
  } = data;
  
  // Set up on first chunk
  if (chunkNumber === 0) {
    fileChunks = new Array(totalChunks);
    expectedChunks = totalChunks;
    fileName = name;
  }
  
  // Decrypt chunk client-side
  const encryptedBytes = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
  const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
  const tagBytes = Uint8Array.from(atob(tag), c => c.charCodeAt(0));
  
  const decryptedChunk = await decryptChunk(encryptedBytes, ivBytes, tagBytes);
  
  // Store chunk
  fileChunks[chunkNumber] = decryptedChunk;
  
  console.log(`Received chunk ${chunkNumber + 1}/${totalChunks}`);
  
  // Check if all chunks received
  const allReceived = fileChunks.every(chunk => chunk !== undefined);
  
  if (allReceived) {
    // Reassemble file
    const blob = new Blob(fileChunks, { type: mimeType });
    
    // Download file
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    
    console.log('✅ File downloaded and decrypted:', fileName);
  }
});
```

---

## 🔒 Security Notes

### What the Server Does NOT Do
❌ **NO encryption/decryption** - All crypto is client-side  
❌ **NO key generation** - Keys generated by clients  
❌ **NO plaintext storage** - Only encrypted data stored  
❌ **NO content inspection** - Server is blind to message content  
❌ **NO content logging** - Only metadata logged  

### What the Server DOES Do
✅ **Relays encrypted data** - Passes ciphertext between users  
✅ **Authenticates users** - JWT token verification  
✅ **Manages connections** - Socket lifecycle  
✅ **Routes messages** - Delivers to correct recipient  
✅ **Logs metadata** - Audit trail (no content)  
✅ **Tracks delivery** - Confirms message receipt  

### Logging Policy
All events are logged to MongoDB with:
- ✅ Event type, timestamp, user ID
- ✅ Session ID, IP address
- ✅ Metadata (seq, chunk number, file size, etc.)
- ❌ NO ciphertext, iv, tag, or decrypted content

---

## 🧪 Testing the WebSocket Server

### 1. Start the Server
```bash
npm run dev
```

### 2. Test with Socket.io Client

```javascript
import { io } from 'socket.io-client';

// Connect
const socket = io('http://localhost:5000', {
  auth: {
    token: 'YOUR_JWT_TOKEN'
  }
});

// Test connection
socket.on('connect', () => {
  console.log('✅ Connected!');
  
  // Test room join
  socket.emit('join_room', { recipientId: 'test_user_id' });
});

socket.on('room:joined', (data) => {
  console.log('✅ Room joined:', data);
  
  // Test message send
  socket.emit('send_message', {
    recipientId: 'test_user_id',
    ciphertext: 'encrypted_test_message',
    iv: 'test_iv',
    tag: 'test_tag',
    seq: 1
  });
});

socket.on('message:sent', (data) => {
  console.log('✅ Message sent:', data);
});

// Test file chunk
socket.emit('send_file_chunk', {
  recipientId: 'test_user_id',
  messageId: 'test_msg',
  chunkNumber: 0,
  totalChunks: 1,
  encryptedData: 'encrypted_test_chunk',
  iv: 'test_iv',
  tag: 'test_tag',
  hash: 'test_hash',
  fileName: 'test.txt',
  fileSize: 1024,
  mimeType: 'text/plain'
});

socket.on('file:chunk-sent', (data) => {
  console.log('✅ File chunk sent:', data);
});
```

### 3. Check Logs

```bash
# View application logs
tail -f server/logs/combined.log

# Check MongoDB logs
mongo infosec_project
db.logs.find().sort({createdAt: -1}).limit(10)
```

---

## 📊 Event Summary

| Event | Direction | Purpose | Logs |
|-------|-----------|---------|------|
| `join_room` | Client → Server | Join 1-1 chat room | Yes |
| `leave_room` | Client → Server | Leave chat room | Yes |
| `send_message` | Client → Server | Send encrypted message | Yes (metadata) |
| `receive_message` | Server → Client | Receive encrypted message | - |
| `send_file_chunk` | Client → Server | Send encrypted file chunk | Yes (metadata) |
| `receive_file_chunk` | Server → Client | Receive encrypted chunk | - |
| `request_file` | Client → Server | Request file download | Yes |
| `key-exchange:send` | Client → Server | Send public key | Yes |
| `key-exchange:receive` | Server → Client | Receive public key | - |
| `typing:start` | Client → Server | Start typing | No |
| `typing:stop` | Client → Server | Stop typing | No |
| `message:delivered` | Client → Server | Confirm delivery | No |
| `message:read` | Client → Server | Confirm read | No |
| `user:online` | Server → Client | User connected | - |
| `user:offline` | Server → Client | User disconnected | - |

---

## 🎯 Summary

✅ **Complete WebSocket implementation**  
✅ **Room-based 1-1 chat**  
✅ **Encrypted message relay** (ciphertext only)  
✅ **Encrypted file chunk relay**  
✅ **Real-time features** (typing, presence)  
✅ **Comprehensive logging** (metadata only)  
✅ **Zero-knowledge architecture**  
✅ **Production-ready**  

The server acts purely as a **relay** - all encryption/decryption happens client-side!

---

**Ready for Integration! 🚀**

See `START_HERE.md` for setup instructions and `API_EXAMPLES.md` for REST API documentation.

