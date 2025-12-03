import { create } from 'zustand';
import { io } from 'socket.io-client';
import { useChatStore } from './chatStore';
import { useAuthStore } from './authStore';
import { parseAndDecryptEnvelope, weakDecryptEnvelope } from '../services/encryptionService';
import { keyExchangeService, waitForSessionKey } from '../services/keyExchangeService';
import { handleIncomingChunk as handleEncryptedChunk } from '../services/fileService';

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:5000';
const seenMessages = new Set(); // dedupe incoming socket messages (senderId:seq:nonce)

export const useSocketStore = create((set, get) => ({
  socket: null,
  isConnected: false,

  connect: () => {
    const token = useAuthStore.getState().token;

    if (!token) {
      console.error('No auth token available for socket connection');
      return;
    }

    const socket = io(SOCKET_URL, {
      auth: { token },
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    // Connection events
    socket.on('connect', () => {
      console.log('Socket connected:', socket.id);
      set({ isConnected: true });
      keyExchangeService.attachSocket(socket);
    });

    socket.on('disconnect', () => {
      console.log('Socket disconnected');
      set({ isConnected: false });
    });

    socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error.message);
      set({ isConnected: false });
    });

    // Room events
    socket.on('room:joined', (data) => {
      console.log('Joined room:', data.roomName);
    });

    socket.on('room:user-ready', (data) => {
      console.log('User ready in room:', data.username);
    });

    // Message events
    socket.on('receive_message', async (data) => {
      console.log('Encrypted message received:', data);

      try {
        const senderId = data.senderId || data.sender_id || data.from;
        const selfUser = useAuthStore.getState().user;
        const recipientId = data.recipientId || data.to || selfUser?.id;
        const sessionKey =
          (await keyExchangeService.getSessionKey(senderId)) ||
          (await waitForSessionKey(senderId, data.senderUsername));
        if (!sessionKey) {
          console.warn('No session key to decrypt message from', senderId);
          return;
        }

        let envelope = null;
        if (data.envelope) {
          envelope = typeof data.envelope === 'string' ? JSON.parse(data.envelope) : data.envelope;
        } else if (data.payload) {
          const ts = Number.isFinite(Number(data.timestamp)) ? Number(data.timestamp) : Date.now();
          envelope = {
            v: data.v || 1,
            sender_id: senderId,
            recipient_id: recipientId,
            nonce: data.nonce || data.nonce_b64 || `live-${Date.now()}`,
            timestamp: ts,
            seq: data.seq || 0,
            payload: data.payload,
          };
        } else if (data.ciphertext && data.iv && data.tag) {
          // Fallback to legacy fields
          const ct = Uint8Array.from(atob(data.ciphertext), (c) => c.charCodeAt(0));
          const iv = Uint8Array.from(atob(data.iv), (c) => c.charCodeAt(0));
          const tag = Uint8Array.from(atob(data.tag), (c) => c.charCodeAt(0));
          const combined = new Uint8Array(ct.byteLength + iv.byteLength + tag.byteLength);
          combined.set(ct, 0);
          combined.set(iv, ct.byteLength);
          combined.set(tag, ct.byteLength + iv.byteLength);
          const bin = String.fromCharCode(...combined);
          envelope = {
            v: 1,
            sender_id: senderId,
            recipient_id: recipientId,
            nonce: data.nonce || `live-${Date.now()}`,
            timestamp: Number.isFinite(Number(data.timestamp)) ? Number(data.timestamp) : Date.now(),
            seq: data.seq || 0,
            payload: btoa(bin),
          };
        }

        if (!envelope) {
          console.warn('Received message without envelope/payload fields');
          return;
        }

        // Drop duplicates (same sender+seq+nonce)
        const dedupeKey = `${senderId}:${envelope.seq ?? data.seq ?? 'na'}:${envelope.nonce || 'na'}`;
        if (seenMessages.has(dedupeKey)) {
          console.log('Dropping duplicate message', dedupeKey);
          return;
        }

        let decrypted;
        try {
          decrypted = await parseAndDecryptEnvelope(envelope, sessionKey);
        } catch (err) {
          console.warn('Live decrypt fallback (weak) for message', err?.message || err);
          decrypted = await weakDecryptEnvelope(envelope, sessionKey);
        }

        const message = {
          id: data.messageId || `msg_${Date.now()}`,
          senderId: data.senderId,
          senderUsername: data.senderUsername,
          text: decrypted,
          messageType: data.messageType || 'text',
          timestamp: envelope.timestamp || data.timestamp || Date.now(),
          seq: envelope.seq || data.seq || 0,
          delivered: false,
          read: false,
          isEncrypted: true,
        };

        seenMessages.add(dedupeKey);
        useChatStore.getState().receiveMessage(message);
      } catch (error) {
        console.error('Failed to decrypt message:', error);
      }
    });

    socket.on('message:sent', (data) => {
      console.log('Message sent:', data);
    });

    // File events
    socket.on('receive_file_chunk', (data) => {
      console.log('File chunk received:', data);
      const senderId = data.senderId || data.sender_id || data.from;
      keyExchangeService.getSessionKey(senderId).then((sessionKey) => {
        if (!sessionKey) {
          console.warn('Missing session key for incoming file chunk from', senderId);
          return;
        }
        handleEncryptedChunk(data, sessionKey, (info) => {
          console.log('File download complete:', info);
        });
      }).catch((err) => console.error('File chunk decrypt error', err));
      useChatStore.getState().receiveFileChunk(data);
    });

    socket.on('file:chunk-sent', (data) => {
      console.log('File chunk sent:', data);
    });

    socket.on('file:upload-complete', (data) => {
      console.log('File upload complete:', data);
    });

    // User presence
    socket.on('user:online', (data) => {
      console.log('User online:', data.username);
      // Update user status in UI
    });

    socket.on('user:offline', (data) => {
      console.log('User offline:', data.username);
      // Update user status in UI
    });

    // Typing indicators
    socket.on('typing:user', (data) => {
      useChatStore.getState().setTypingUser(data.userId, data.isTyping);
    });

    // Key exchange
    socket.on('key-exchange:receive', (data) => {
      keyExchangeService.handleInbound(data).catch((err) => console.error('Key exchange receive error', err));
    });

    // Delivery confirmations
    socket.on('message:delivery-confirmed', (data) => {
      useChatStore.getState().updateMessageStatus(data.messageId, {
        delivered: true,
      });
    });

    socket.on('message:read-confirmed', (data) => {
      useChatStore.getState().updateMessageStatus(data.messageId, {
        read: true,
      });
    });

    // Error events
    socket.on('message:error', (data) => {
      console.error('Message error:', data.error);
      alert(`Message error: ${data.error}`);
    });

    socket.on('file:error', (data) => {
      console.error('File error:', data.error);
      alert(`File error: ${data.error}`);
    });

    socket.on('room:error', (data) => {
      console.error('Room error:', data.error);
    });

    set({ socket });
  },

  disconnect: () => {
    const { socket } = get();
    if (socket) {
      socket.disconnect();
      set({ socket: null, isConnected: false });
    }
  },

  joinRoom: (recipientId) => {
    const { socket } = get();
    if (socket && socket.connected) {
      socket.emit('join_room', { recipientId });
    }
  },

  leaveRoom: (recipientId) => {
    const { socket } = get();
    if (socket && socket.connected) {
      socket.emit('leave_room', { recipientId });
    }
  },

  sendTypingStart: (recipientId) => {
    const { socket } = get();
    if (socket && socket.connected) {
      socket.emit('typing:start', { recipientId });
    }
  },

  sendTypingStop: (recipientId) => {
    const { socket } = get();
    if (socket && socket.connected) {
      socket.emit('typing:stop', { recipientId });
    }
  },
}));
