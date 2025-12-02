# Quick Reference Card

## 🚀 Start Server

```bash
npm install           # First time only
npm run dev          # Development (auto-reload)
npm start            # Production
```

## 🔑 Environment Variables (.env)

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/infosec_project
JWT_SECRET=your_secret_key_here
JWT_EXPIRE=7d
CORS_ORIGIN=http://localhost:3000
```

## 📡 Common API Calls

### Register
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Alice@123"}'
```

### Login
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Alice@123"}'
```

### Send Message (Save token first!)
```bash
TOKEN="your_jwt_token_here"
curl -X POST http://localhost:5000/api/messages/send \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"recipientId":"USER_ID","ciphertext":"ENCRYPTED","iv":"IV","tag":"TAG","seq":1}'
```

### Get Conversations
```bash
curl http://localhost:5000/api/messages/conversations \
  -H "Authorization: Bearer $TOKEN"
```

## 🔌 Socket.io (JavaScript)

```javascript
import { io } from 'socket.io-client';

const socket = io('http://localhost:5000', {
  auth: { token: 'YOUR_JWT_TOKEN' }
});

// Join room
socket.emit('join_room', { recipientId: 'USER_ID' });

// Send encrypted message (ciphertext only)
socket.emit('send_message', {
  recipientId: 'USER_ID',
  ciphertext: 'ENCRYPTED_DATA',
  iv: 'IV_BASE64',
  tag: 'TAG_BASE64',
  seq: 1
});

// Send encrypted file chunk
socket.emit('send_file_chunk', {
  recipientId: 'USER_ID',
  messageId: 'MSG_ID',
  chunkNumber: 0,
  totalChunks: 5,
  encryptedData: 'ENCRYPTED_CHUNK',
  iv: 'IV_BASE64',
  tag: 'TAG_BASE64',
  hash: 'HASH',
  fileName: 'file.pdf',
  fileSize: 1024,
  mimeType: 'application/pdf'
});

// Receive encrypted message
socket.on('receive_message', (data) => {
  // Decrypt client-side
  const plaintext = decrypt(data.ciphertext, data.iv, data.tag);
  console.log('Message:', plaintext);
});

// Receive encrypted file chunk
socket.on('receive_file_chunk', (data) => {
  // Decrypt chunk client-side
  const chunk = decrypt(data.encryptedData, data.iv, data.tag);
  console.log(`Chunk ${data.chunkNumber + 1}/${data.totalChunks}`);
});
```

## 📁 Project Structure

```
server/
├── server.js           # Main entry point
├── config/            # Configuration
├── models/            # Database models
├── controllers/       # Business logic
├── routes/           # API routes
├── middlewares/      # Express middlewares
├── sockets/          # Socket.io handlers
└── utils/            # Utilities
```

## 🗄️ Key Models

### User
- username, email, password (hashed)
- publicKey, isOnline, lastSeen

### Message (Encrypted Only!)
- sender, recipient
- ciphertext, iv, tag, seq
- delivered, read, timestamps

### FileChunk
- chunkNumber, totalChunks
- encryptedData, iv, tag
- size, hash

## 🔒 Security Checklist

- ✅ Passwords: bcrypt work factor 12
- ✅ Auth: JWT tokens required
- ✅ Storage: NO plaintext (encrypted only)
- ✅ Replay: Sequence numbers checked
- ✅ Rate Limit: 5 auth attempts/15min
- ✅ Validation: All inputs validated
- ✅ Logging: All events logged

## 🐛 Debugging

### Check Logs
```bash
tail -f server/logs/combined.log     # All logs
tail -f server/logs/error.log        # Errors only
```

### Check MongoDB
```bash
mongo
use infosec_project
db.users.find()
db.messages.find()
db.logs.find().sort({createdAt:-1}).limit(10)
```

### Common Issues

**Port in use:**
```bash
# Kill process on port 5000
# Windows: netstat -ano | findstr :5000
# Linux/Mac: lsof -i :5000
```

**MongoDB not running:**
```bash
# Windows: net start MongoDB
# Mac: brew services start mongodb-community
# Linux: sudo systemctl start mongod
```

**Module not found:**
```bash
rm -rf node_modules package-lock.json
npm install
```

## 📊 Rate Limits

| Endpoint | Limit |
|----------|-------|
| General API | 100/15min |
| Auth (/login, /register) | 5/15min |
| Messages | 30/min |

## 🔐 Password Requirements

- Minimum 8 characters
- 1 uppercase letter
- 1 lowercase letter
- 1 number
- 1 special character

Example: `Test@1234`

## 🎯 Socket Events Reference

### Emit (Client → Server)
- `join_room` - Join 1-1 chat room
- `leave_room` - Leave chat room
- `send_message` - Send encrypted message
- `send_file_chunk` - Send encrypted file chunk
- `request_file` - Request file download
- `key-exchange:send` - Send public key
- `typing:start` - Start typing
- `typing:stop` - Stop typing
- `message:delivered` - Confirm delivery
- `message:read` - Confirm read

### Listen (Server → Client)
- `room:joined` - Room joined successfully
- `room:left` - Room left successfully
- `room:user-ready` - User ready to chat
- `receive_message` - Receive encrypted message
- `receive_file_chunk` - Receive encrypted file chunk
- `file:chunk-sent` - Chunk sent confirmation
- `file:upload-complete` - All chunks sent
- `file:requested` - File download requested
- `user:online` - User connected
- `user:offline` - User disconnected
- `key-exchange:receive` - Receive key
- `typing:user` - User typing status
- `message:delivery-confirmed` - Message delivered
- `message:read-confirmed` - Message read

## 📞 Health Check

```bash
curl http://localhost:5000/health
```

Expected:
```json
{"success":true,"message":"Server is running"}
```

## 🔢 HTTP Status Codes

- **200** OK
- **201** Created
- **400** Bad Request (validation error)
- **401** Unauthorized (no/invalid token)
- **403** Forbidden (valid token, no permission)
- **404** Not Found
- **409** Conflict (duplicate)
- **429** Too Many Requests (rate limit)
- **500** Server Error

## 📚 Full Documentation

- `README.md` - Complete documentation
- `SETUP.md` - Setup instructions
- `API_EXAMPLES.md` - Detailed API examples
- `PROJECT_SUMMARY.md` - Project overview

## 💡 Tips

1. **Always use HTTPS in production**
2. **Change JWT_SECRET before deployment**
3. **Enable MongoDB authentication**
4. **Set up log rotation**
5. **Monitor rate limits**
6. **Check logs regularly**

## 🆘 Emergency Commands

```bash
# Stop server: Ctrl+C

# Check if server is running
curl http://localhost:5000/health

# View last 50 logs
tail -50 server/logs/combined.log

# Check MongoDB connection
mongo infosec_project --eval "db.stats()"

# Reset database (CAREFUL!)
mongo infosec_project --eval "db.dropDatabase()"
```

---

**Keep this handy! 📌**

