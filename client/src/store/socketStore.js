import { create } from 'zustand';
import { io } from 'socket.io-client';
import { useChatStore } from './chatStore';
import { useAuthStore } from './authStore';
import { decryptMessage } from '../utils/crypto';

const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:5000';

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
      auth: {
        token,
      },
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    // Connection events
    socket.on('connect', () => {
      console.log('✅ Socket connected:', socket.id);
      set({ isConnected: true });
    });

    socket.on('disconnect', () => {
      console.log('❌ Socket disconnected');
      set({ isConnected: false });
    });

    socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error.message);
      set({ isConnected: false });
    });

    // Room events
    socket.on('room:joined', (data) => {
      console.log('✅ Joined room:', data.roomName);
    });

    socket.on('room:user-ready', (data) => {
      console.log('👤 User ready in room:', data.username);
    });

    // Message events
    socket.on('receive_message', async (data) => {
      console.log('📨 Encrypted message received:', data);

      try {
        // NOTE: Placeholder decryption function
        // Members 1 & 2 will implement actual decryption
        const decrypted = await decryptMessage(
          data.ciphertext,
          data.iv,
          data.tag
        );

        const message = {
          id: `msg_${Date.now()}`,
          senderId: data.senderId,
          senderUsername: data.senderUsername,
          text: decrypted,
          messageType: data.messageType || 'text',
          timestamp: data.timestamp,
          delivered: false,
          read: false,
          isEncrypted: true,
        };

        useChatStore.getState().receiveMessage(message);
      } catch (error) {
        console.error('Failed to decrypt message:', error);
      }
    });

    socket.on('message:sent', (data) => {
      console.log('✅ Message sent:', data);
    });

    // File events
    socket.on('receive_file_chunk', (data) => {
      console.log('📎 File chunk received:', data);
      useChatStore.getState().receiveFileChunk(data);
    });

    socket.on('file:chunk-sent', (data) => {
      console.log('✅ File chunk sent:', data);
    });

    socket.on('file:upload-complete', (data) => {
      console.log('✅ File upload complete:', data);
    });

    // User presence
    socket.on('user:online', (data) => {
      console.log('👋 User online:', data.username);
      // Update user status in UI
    });

    socket.on('user:offline', (data) => {
      console.log('👋 User offline:', data.username);
      // Update user status in UI
    });

    // Typing indicators
    socket.on('typing:user', (data) => {
      useChatStore.getState().setTypingUser(data.userId, data.isTyping);
    });

    // Key exchange
    socket.on('key-exchange:receive', (data) => {
      console.log('🔑 Public key received from:', data.senderUsername);
      // TODO: Store public key and verify signature
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
      console.error('❌ Message error:', data.error);
      alert(`Message error: ${data.error}`);
    });

    socket.on('file:error', (data) => {
      console.error('❌ File error:', data.error);
      alert(`File error: ${data.error}`);
    });

    socket.on('room:error', (data) => {
      console.error('❌ Room error:', data.error);
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

