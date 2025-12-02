# 🔒 Secure Messaging App - Frontend

React frontend for the Information Security Course Project - Secure Messaging System.

## 🎯 Member 3 Responsibilities

This frontend skeleton includes:
- ✅ Complete UI components
- ✅ Socket.io client integration
- ✅ State management (Zustand)
- ✅ API integration (Axios)
- ✅ **Placeholder encryption functions**

**Note**: Members 1 & 2 will implement the actual cryptographic functions.

---

## 📦 Tech Stack

- **React** 18.2 - UI framework
- **Vite** 5.0 - Build tool
- **React Router** 6.21 - Routing
- **Socket.io Client** 4.6 - Real-time communication
- **Zustand** 4.4 - State management
- **Axios** 1.6 - HTTP client

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd client
npm install
```

### 2. Configure Environment

```bash
# Copy example env file
cp .env.example .env

# Edit .env if needed (default values should work)
```

### 3. Start Development Server

```bash
npm run dev
```

Frontend will start on `http://localhost:3000`

### 4. Build for Production

```bash
npm run build
```

---

## 📁 Project Structure

```
client/
├── public/                 # Static assets
├── src/
│   ├── components/         # React components
│   │   ├── MessageList.jsx
│   │   ├── MessageInput.jsx
│   │   ├── FileUpload.jsx
│   │   └── UserSidebar.jsx
│   ├── pages/             # Page components
│   │   ├── Login.jsx
│   │   ├── Register.jsx
│   │   └── Chat.jsx
│   ├── store/             # Zustand stores
│   │   ├── authStore.js
│   │   ├── chatStore.js
│   │   └── socketStore.js
│   ├── services/          # API services
│   │   └── api.js
│   ├── utils/             # Utility functions
│   │   └── crypto.js      # ⚠️ PLACEHOLDER (Members 1 & 2)
│   ├── styles/            # CSS files
│   │   ├── Auth.css
│   │   ├── Chat.css
│   │   ├── MessageList.css
│   │   ├── MessageInput.css
│   │   ├── FileUpload.css
│   │   └── UserSidebar.css
│   ├── App.jsx            # Main app component
│   ├── main.jsx           # Entry point
│   └── index.css          # Global styles
├── package.json
├── vite.config.js
└── README.md
```

---

## 🔑 Key Features

### Implemented

- ✅ **User Authentication**
  - Login/Register pages
  - JWT token storage
  - Protected routes

- ✅ **Chat Interface**
  - Real-time messaging UI
  - User sidebar with search
  - Message list with timestamps
  - File upload modal
  - Typing indicators (UI ready)

- ✅ **Socket.io Integration**
  - Connection management
  - Message relay
  - File chunk relay
  - User presence
  - Event handlers

- ✅ **State Management**
  - Auth state (Zustand)
  - Chat state (Zustand)
  - Socket state (Zustand)

### ⚠️ Placeholder Functions (For Members 1 & 2)

Located in `src/utils/crypto.js`:

```javascript
// These are MOCK implementations
// Members 1 & 2 need to implement:

encryptMessage()      // TODO: AES-GCM encryption
decryptMessage()      // TODO: AES-GCM decryption
encryptFile()         // TODO: File encryption
decryptFileChunk()    // TODO: File decryption
generateKeyPair()     // TODO: RSA/ECDH key generation
signData()            // TODO: Digital signatures
verifySignature()     // TODO: Signature verification
```

**Current behavior**: Messages are Base64 encoded (NOT SECURE!)

---

## 🔌 Socket.io Events

### Emit (Client → Server)

```javascript
// Join room
socket.emit('join_room', { recipientId });

// Send encrypted message
socket.emit('send_message', {
  recipientId,
  ciphertext,  // Encrypted
  iv,
  tag,
  seq,
  messageType
});

// Send encrypted file chunk
socket.emit('send_file_chunk', {
  recipientId,
  messageId,
  chunkNumber,
  totalChunks,
  encryptedData,  // Encrypted
  iv,
  tag,
  hash,
  fileName,
  fileSize,
  mimeType
});
```

### Listen (Server → Client)

```javascript
// Receive encrypted message
socket.on('receive_message', (data) => {
  // data.ciphertext - decrypt this!
});

// Receive encrypted file chunk
socket.on('receive_file_chunk', (data) => {
  // data.encryptedData - decrypt this!
});

// User presence
socket.on('user:online', (data) => { ... });
socket.on('user:offline', (data) => { ... });
```

---

## 🎨 UI Components

### Pages

**Login** (`/login`)
- Email and password fields
- Password strength validation
- Error handling
- Redirect to chat on success

**Register** (`/register`)
- Username, email, password fields
- OWASP password validation
- Confirm password
- Error handling

**Chat** (`/chat`)
- User sidebar
- Message list
- Message input
- File upload modal
- Connection status indicator

### Components

**UserSidebar**
- User search
- Conversation list
- Online/offline status
- Unread message badges

**MessageList**
- Scrollable message feed
- Date dividers
- Message bubbles (own/other)
- File message indicators
- Encryption badges
- Delivery/read receipts

**MessageInput**
- Text input with auto-resize
- Send button
- Encryption notice
- Enter to send

**FileUpload**
- Drag & drop zone
- File preview
- Upload progress bar
- Chunk-by-chunk upload
- Max 10MB limit

---

## 🔐 Security Notes

### What IS Implemented

- ✅ JWT authentication
- ✅ Token storage
- ✅ Protected routes
- ✅ HTTPS ready
- ✅ Input validation

### What is NOT Implemented (Yet)

- ❌ **Message encryption** - Placeholder only
- ❌ **File encryption** - Placeholder only
- ❌ **Key generation** - Placeholder only
- ❌ **Digital signatures** - Placeholder only

**Members 1 & 2**: Replace placeholder functions in `src/utils/crypto.js`

---

## 🧪 Testing

### Manual Testing

1. **Start Backend**
   ```bash
   cd ../server
   npm run dev
   ```

2. **Start Frontend**
   ```bash
   npm run dev
   ```

3. **Test Flow**
   - Register a new user
   - Login
   - Search for another user
   - Send a message (will use mock encryption)
   - Upload a file (will use mock encryption)

---

## 🔧 Configuration

### Environment Variables

```env
# Backend API
VITE_API_URL=http://localhost:5000/api

# Socket.io server
VITE_SOCKET_URL=http://localhost:5000
```

### Proxy Configuration

Vite proxies `/api` requests to backend (see `vite.config.js`)

---

## 📚 Integration Guide for Members 1 & 2

### Step 1: Implement Encryption Functions

Replace placeholders in `src/utils/crypto.js`:

```javascript
// Implement real AES-GCM encryption
export async function encryptMessage(plaintext, recipientId) {
  // TODO: Get recipient's public key
  // TODO: Generate shared secret (ECDH)
  // TODO: Encrypt with AES-GCM
  // TODO: Return { ciphertext, iv, tag }
}

// Implement real AES-GCM decryption
export async function decryptMessage(ciphertext, iv, tag) {
  // TODO: Get sender's public key
  // TODO: Generate shared secret (ECDH)
  // TODO: Decrypt with AES-GCM
  // TODO: Return plaintext
}
```

### Step 2: Implement Key Management

```javascript
// Generate key pair on registration
const { publicKey, privateKey } = await generateKeyPair();

// Store private key securely (localStorage/IndexedDB)
localStorage.setItem('privateKey', privateKey);

// Send public key to server
await authAPI.updatePublicKey(publicKey);
```

### Step 3: Test Encryption

1. Generate keys for two users
2. Exchange public keys
3. Send encrypted message
4. Verify recipient can decrypt

---

## 🎯 Current Status

### ✅ Complete (Member 3)
- React components and UI
- Socket.io integration
- State management
- API integration
- Styling and layout
- Mock encryption (for testing)

### ⏭️ TODO (Members 1 & 2)
- Implement `encryptMessage()`
- Implement `decryptMessage()`
- Implement `encryptFile()`
- Implement `decryptFileChunk()`
- Implement key generation
- Implement digital signatures
- Add key management UI
- Add encryption indicators

---

## 🆘 Troubleshooting

### Backend Connection Failed
- Ensure backend is running on `http://localhost:5000`
- Check CORS configuration in backend
- Verify `VITE_API_URL` in `.env`

### Socket.io Not Connecting
- Check if backend Socket.io server is running
- Verify JWT token is valid
- Check browser console for errors

### Messages Not Decrypting
- This is expected! Using placeholder encryption
- Members 1 & 2 need to implement real crypto

---

## 📖 References

- **React**: https://react.dev
- **Socket.io Client**: https://socket.io/docs/v4/client-api/
- **Zustand**: https://github.com/pmndrs/zustand
- **Vite**: https://vitejs.dev

---

## 🎉 Ready for Integration!

The UI skeleton is complete and ready for cryptographic implementation by Members 1 & 2.

**Backend must be running** for full functionality.

**Good luck with the encryption! 🔐**

