# 🔒 Secure End-to-End Encrypted Messaging & File Sharing System

A full-stack, **end-to-end encrypted** messaging and file-sharing application built with Node.js, React, MongoDB, and Socket.io for an Information Security course project. The server is a **zero-knowledge relay** — it never sees plaintext, keys, or decrypted content.

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-6+-green.svg)](https://www.mongodb.com/)
[![Socket.io](https://img.shields.io/badge/Socket.io-4.6+-black.svg)](https://socket.io/)
[![Crypto](https://img.shields.io/badge/Crypto-AES--GCM%20%2B%20ECDH-purple.svg)](#-cryptography--security)

---

## 🎯 Overview

A complete secure messenger where **all cryptography runs client-side** in the browser using the Web Crypto API. The backend only stores and relays opaque ciphertext.

- **Backend** — Node.js + Express + MongoDB + Socket.io (relay + metadata store)
- **Frontend** — React 18 + Vite + Zustand, with a modern animated UI (Framer Motion)
- **Real-time** — Socket.io for instant delivery, presence, typing, and group sync
- **Crypto** — AES-256-GCM, ECDH key exchange, a per-message KDF ratchet, and ECDSA signatures — all in the browser

---

## ✨ Features

### Messaging
- 💬 **1-on-1 end-to-end encrypted chat** with real-time delivery
- 👥 **Group chat** — E2E encrypted via pairwise fan-out (each member's copy encrypted with their own session key; server stays zero-knowledge)
- ⚙️ **Group management** — create, rename, add/remove members, leave (with ownership transfer & auto-delete when empty), all synced live
- 📎 **Encrypted file sharing** — chunked upload, relay, reassembly, and auto-download
- ✍️ **Typing indicators** — live bouncing-dots indicator
- ✅ **Read receipts** — sent (🕐) → delivered (✓) → read (✓✓)
- 🟢 **Online/offline presence** — live status dots
- 🗂️ **Persistent conversation list** with unread badges
- 🕘 **Persistent message history** — a local decrypted-message cache keeps history readable across reloads and key rotation

### Security & Cryptography
- 🔐 **AES-256-GCM** authenticated encryption (Web Crypto API)
- 🤝 **ECDH (P-256) key exchange** — signed handshake + key-confirmation MAC
- 🔁 **Per-message KDF ratchet** — every message encrypted under a unique key derived from the session key + sequence number (versioned `v2` envelopes)
- 🖊️ **ECDSA (P-256) digital signatures** on every message → a **🛡️ verified-sender badge**
- 🧭 **Safety-number / fingerprint verification** — compare a number out-of-band to detect man-in-the-middle attacks
- 🛡️ **Replay protection** — random nonces + monotonic sequence numbers, with server-enforced `(sender, recipient, seq)` uniqueness
- 🕵️ **Zero-knowledge server** — only ciphertext/IV/tag/metadata stored; never plaintext or keys
- 🔑 **Auth hardening** — JWT auth, bcrypt password hashing, rate limiting, Helmet, CORS, and a security audit log

### UI
- 🎨 Modern **dark glassmorphism** theme with gradient accents
- ⚡ **Framer Motion** animations — page transitions, message enter/exit, list reordering, gesture feedback
- 📱 Responsive layout

---

## 🏗️ Architecture (Zero-Knowledge)

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client A   │         │   Backend    │         │   Client B   │
│   (React)    │         │  (Node.js)   │         │   (React)    │
├──────────────┤         ├──────────────┤         ├──────────────┤
│ ECDH + sign  │────────▶│  Store only  │         │              │
│ AES-GCM enc  │  HTTPS  │  ciphertext  │ Socket  │ Verify sig   │
│              │         │  + metadata  │────────▶│ AES-GCM dec  │
│ Verify sig   │◀────────│  Relay msgs  │         │              │
│ AES-GCM dec  │         │  (no keys)   │         │              │
└──────────────┘         └──────────────┘         └──────────────┘
```

**Key principle:** the server **never** decrypts. Key exchange, encryption, signing, and verification all happen in the browser.

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- A MongoDB instance — either **MongoDB Atlas** (free cloud) or a local one via Docker

### 1. Clone & install
```bash
git clone https://github.com/saif2012004/Secure-End-to-End-Encrypted-Messaging-File-Sharing-System.git
cd Secure-End-to-End-Encrypted-Messaging-File-Sharing-System

npm install          # backend deps
cd client && npm install && cd ..   # frontend deps
```

### 2. Start MongoDB (pick one)
```bash
# Option A — local via Docker (quickest)
docker run -d --name securechat-mongo -p 27017:27017 mongo:7

# Option B — MongoDB Atlas (free cloud): create a cluster and grab the connection string.
# See ⚡_SETUP_AND_RUN.md for the step-by-step.
```

### 3. Create a `.env` in the project root
```env
PORT=5000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/infosec_project   # or your Atlas URI
JWT_SECRET=replace_with_a_long_random_string
JWT_EXPIRE=7d
CORS_ORIGIN=http://localhost:3000
SOCKET_CORS_ORIGIN=http://localhost:3000
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100
```

### 4. Run
```bash
# Terminal 1 — backend
npm run dev          # or: npm start

# Terminal 2 — frontend
cd client && npm run dev
```

Open **http://localhost:3000**, register two users (in two browsers / a normal + incognito window), and start chatting. 🎉

---

## 📁 Project Structure

```
Secure-Messaging-System/
│
├── server/                         # Backend (Node.js + Express + Socket.io)
│   ├── config/                     # DB, CORS, rate limiting
│   ├── controllers/                # auth, message, file, group logic
│   ├── routes/                     # REST endpoints (auth, messages, files, groups)
│   ├── models/                     # User, Message, Group, FileChunk, Log
│   ├── middlewares/                # auth, validation, logging, security
│   ├── sockets/                    # Socket.io relay (messages, presence, typing, groups)
│   ├── utils/                      # logger, JWT, validation
│   └── server.js                   # entry point
│
├── client/                         # Frontend (React + Vite)
│   └── src/
│       ├── pages/                  # Login, Register, Chat
│       ├── components/             # MessageList, MessageInput, UserSidebar, TypingIndicator,
│       │                           #   FileUpload, CreateGroupModal, GroupManageModal, SafetyNumberModal
│       ├── crypto/                 # aesGcm, messageFormat, fileEncryption, random, constants
│       ├── services/               # encryptionService, keyExchangeService, safetyNumber,
│       │                           #   messageCache, fileService, api
│       ├── store/                  # Zustand stores: auth, chat, group, socket
│       ├── animations/             # Framer Motion variants
│       └── styles/                 # CSS (dark glass theme)
│
├── demo/                           # replay-attack demonstration scripts
├── mitm-demos/                     # man-in-the-middle demonstration scripts
├── .gitignore                      # ignores .env, node_modules, dist, logs
├── package.json                    # backend
└── README.md
```

---

## 🔐 Cryptography & Security

| Layer | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM (Web Crypto), unique random IV per message |
| **Key agreement** | ECDH P-256, HKDF-derived session key, signed handshake + key-confirmation MAC |
| **Forward-ish secrecy** | Per-message KDF ratchet — `messageKey = HKDF(sessionKey, seq)` (versioned `v2` envelopes) |
| **Authenticity** | ECDSA P-256 signatures over each ciphertext → verified-sender badge |
| **MITM detection** | Safety number derived from both identity public keys (compare out-of-band) |
| **Replay protection** | Random nonces + monotonic seq; server enforces unique `(sender, recipient, seq)` |
| **At rest (server)** | Only ciphertext, IV, tag, and metadata — never plaintext or keys |
| **Auth** | JWT + bcrypt; rate limiting, Helmet, CORS; security audit logging |

> **Note:** the per-message ratchet provides key separation per message (not a full Double-Ratchet, since the root session key persists for usability). History is kept readable via a local decrypted-message cache on each device.

---

## 📡 REST API (overview)

**Auth** — `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `PUT /api/auth/public-key`, `GET /api/auth/user/:id`, `GET /api/auth/users/search`

**Messages** — `POST /api/messages/send`, `GET /api/messages/conversations`, `GET /api/messages/conversation/:userId`, `PATCH /api/messages/:id/delivered`, `PATCH /api/messages/:id/read`, `DELETE /api/messages/:id`

**Groups** — `POST /api/groups`, `GET /api/groups`, `GET /api/groups/:id/messages`, `POST /api/groups/:id/messages`, `PATCH /api/groups/:id` (rename), `POST /api/groups/:id/members` (add), `DELETE /api/groups/:id/members/:memberId` (remove), `POST /api/groups/:id/leave`

**Files** — `POST /api/files/upload-chunk`, `GET /api/files/download/:id`, `GET /api/files/progress/:id`, `DELETE /api/files/:id`

**Health** — `GET /health`, `GET /`

---

## 🔌 Socket.io Events (overview)

**Client → Server:** `join_room`, `leave_room`, `send_message`, `send_file_chunk`, `request_file`, `key-exchange:send`, `typing:start`, `typing:stop`, `message:delivered`, `message:read`

**Server → Client:** `receive_message`, `receive_file_chunk`, `key-exchange:receive`, `user:online`, `user:offline`, `typing:user`, `message:delivery-confirmed`, `message:read-confirmed`, `group:created`, `group:updated`, `group:removed`, `group_message`, plus connection/error events

---

## 🗄️ Data Models (metadata only — no plaintext)

- **User** — username, email, bcrypt password hash, online status, lastSeen
- **Message** — sender, recipient, optional `group`, ciphertext / iv / tag / payload, `seq`, `nonce`, `signature`, `v` (crypto version), delivered/read flags
- **Group** — name, owner, members[], avatar color
- **FileChunk** — messageId, chunk index, encrypted data, iv, tag
- **Log** — security event type, level, user, IP, success, details

---

## 🛠️ Tech Stack

**Backend:** Node.js, Express, MongoDB + Mongoose, Socket.io, JWT, bcrypt, Winston, Helmet, express-rate-limit, express-validator

**Frontend:** React 18, Vite, Zustand, Axios, socket.io-client, React Router, Framer Motion, Web Crypto API

---

## 🧪 Testing

1. Start the backend and frontend.
2. Register **alice** and **bob** in two separate browser sessions.
3. Search for the other user, open the chat, and send a message — it appears instantly and decrypts on the other side.
4. Try the security features: open **🛡️ Verify** to compare safety numbers, watch the **✓✓** read receipts, the **🛡️ verified-sender** badge, typing indicators, and create a **group** to message multiple people.

### Security demonstrations
Standalone Node scripts that demonstrate the security properties (great for a report):

```bash
node demo/replay-attack-success.js          # replay protection accepts once, rejects replays
node demo/replay-attack-fail-insecure.js    # without protection, a replay is accepted
node mitm-demos/mitm-attack-insecure.js     # unauthenticated key exchange is hijacked by a MITM
node mitm-demos/mitm-attack-secured.js      # signed key exchange detects and blocks the MITM
```

---

## ⚠️ Notes

- **Never commit `.env`** — it's gitignored. It holds your MongoDB URI and JWT secret.
- This is an **educational project**. The crypto demonstrates real, working primitives (AES-GCM, ECDH, ECDSA, HKDF ratchet) but has not undergone a formal security audit.

---

## 🎓 Course

**Course:** Information Security · **Project:** Secure End-to-End Encrypted Messaging System

---

**Built with ❤️ for an Information Security course.**
