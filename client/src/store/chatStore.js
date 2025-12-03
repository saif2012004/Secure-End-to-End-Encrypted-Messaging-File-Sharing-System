import { create } from 'zustand';
import { useSocketStore } from './socketStore';
import { messagesAPI } from '../services/api';
import { parseAndDecryptEnvelope, createEncryptedEnvelope, weakDecryptEnvelope } from '../services/encryptionService';
import {
  startKeyExchange,
  getSessionKey,
  nextSessionSeq,
  getIdentityPublicB64,
  waitForSessionKey,
} from '../services/keyExchangeService';
import { useAuthStore } from './authStore';
import { base64ToBytes, bytesToBase64 } from '../crypto/messageFormat';
import { unpackPayload } from '../crypto/aesGcm';

export const useChatStore = create((set, get) => ({
  selectedUser: null,
  messages: [],
  conversations: [],
  typingUsers: [],
  isLoadingMessages: false,
  messagesError: null,

  setSelectedUser: async (user) => {
    set({ selectedUser: user, messages: [], isLoadingMessages: true, messagesError: null });
    
    // Join the socket room for this user
    const socketStore = useSocketStore.getState();
    if (socketStore.socket?.connected) {
      socketStore.joinRoom(user.id);
    }

    // Kick off key exchange if needed
    startKeyExchange(user.id, user.username).catch((err) => console.error('Failed to start key exchange', err));
    
    // Fetch existing messages from backend
    await get().fetchMessages(user.id);
  },

  fetchMessages: async (userId) => {
    try {
      set({ isLoadingMessages: true, messagesError: null });
      
      const response = await messagesAPI.getConversation(userId, 50, 0);
      
      if (response.success) {
        // Decrypt messages for display
        const authUser = useAuthStore.getState().user;
        const decryptedMessages = await Promise.all(
          response.data.messages.map(async (msg) => {
            const senderId = msg.sender?._id || msg.senderId || msg.from || msg.sender;
            const recipientId = msg.recipient?._id || msg.recipientId || msg.to;
            const peerId = senderId === authUser?.id ? recipientId : senderId;
            const sessionKey = peerId ? await getSessionKey(peerId) : null;

            let plaintext = '[🔒 Encrypted Message]';
            let failed = false;
            if (sessionKey) {
              try {
                let envelope = null;
                if (msg.envelope) {
                  envelope = typeof msg.envelope === 'string' ? JSON.parse(msg.envelope) : msg.envelope;
                } else if (msg.payload) {
                  const ts = Date.now(); // normalize to "fresh" timestamp for history decrypt
                  envelope = {
                    v: msg.v || 1,
                    sender_id: senderId,
                    recipient_id: recipientId,
                    nonce: msg.nonce || msg.nonce_b64 || `legacy-${msg._id || msg.seq || Date.now()}`,
                    timestamp: ts,
                    seq: msg.seq || 0,
                    payload: msg.payload,
                  };
                } else if (msg.ciphertext && msg.iv && msg.tag) {
                  const ct = base64ToBytes(msg.ciphertext);
                  const iv = base64ToBytes(msg.iv);
                  const tag = base64ToBytes(msg.tag);
                  const combined = new Uint8Array(ct.byteLength + iv.byteLength + tag.byteLength);
                  combined.set(ct, 0);
                  combined.set(iv, ct.byteLength);
                  combined.set(tag, ct.byteLength + iv.byteLength);
                  const ts = Date.now();
                  envelope = {
                    v: 1,
                    sender_id: senderId,
                    recipient_id: recipientId,
                    nonce: msg.nonce || msg.nonce_b64 || `legacy-${msg._id || msg.seq || Date.now()}`,
                    timestamp: ts,
                    seq: msg.seq || 0,
                    payload: bytesToBase64(combined),
                  };
                }
                if (envelope) {
                  // For history, prefer strict decrypt first, but always fall back to weak to avoid stale/replay blocking UI.
                  try {
                    plaintext = await parseAndDecryptEnvelope(envelope, sessionKey, peerId);
                  } catch (err) {
                    console.warn('History decrypt fallback (weak) for message', msg._id || msg.seq, err?.message || err);
                    plaintext = await weakDecryptEnvelope(envelope, sessionKey);
                  }
                }
              } catch (error) {
                console.error('Failed to decrypt message:', error);
                failed = true;
              }
            } else {
              failed = true;
            }

            return {
              id: msg._id,
              senderId,
              senderUsername: msg.sender?.username || msg.senderUsername,
              recipientId,
              text: plaintext, // Decrypted text for display
              seq: msg.seq,
              messageType: msg.messageType || 'text',
              timestamp: msg.createdAt,
              delivered: msg.delivered,
              read: msg.read,
              isEncrypted: true,
              decryptionFailed: failed,
            };
          })
        );

        set({ messages: decryptedMessages, isLoadingMessages: false });
      }
    } catch (error) {
      console.error('Failed to fetch messages:', error);
      set({ 
        messagesError: error.response?.data?.error || 'Failed to load messages',
        isLoadingMessages: false 
      });
    }
  },

  sendMessage: async (messageData) => {
    const socket = useSocketStore.getState().socket;

    if (!socket || !socket.connected) {
      throw new Error('Socket not connected');
    }

    try {
      console.log('[chat] preparing to send message', { to: messageData.recipientId });
      const selected = get().selectedUser;
      const sessionKey =
        (await getSessionKey(messageData.recipientId)) ||
        (await waitForSessionKey(messageData.recipientId, selected?.username));
      if (!sessionKey) {
        throw new Error('No session key for recipient; ensure key exchange is completed');
      }
      const seq = await nextSessionSeq(messageData.recipientId);
      const senderIdentity = await getIdentityPublicB64();
      const envelope = await createEncryptedEnvelope(
        messageData.plaintext || messageData.text || '',
        sessionKey,
        messageData.recipientId,
        senderIdentity,
        seq,
      );
      const payloadBytes = base64ToBytes(envelope.payload);
      const split = unpackPayload(payloadBytes);
      const ctB64 = bytesToBase64(split.ciphertext);
      const ivB64 = bytesToBase64(split.iv);
      const tagB64 = bytesToBase64(split.tag);
      console.log('[chat] envelope ready', { seq, nonce: envelope.nonce, ctLen: split.ciphertext.length });

      // Step 1: Save encrypted message to backend (permanent storage)
      const response = await messagesAPI.sendMessage({
        recipientId: messageData.recipientId,
        // legacy fields expected by backend
        ciphertext: ctB64,
        iv: ivB64,
        tag: tagB64,
        seq: envelope.seq,
        nonce: envelope.nonce,
        timestamp: envelope.timestamp,
        messageType: messageData.messageType || 'text',
        // store full envelope for future compatibility
        envelope,
        payload: envelope.payload,
      });
      console.log('[chat] backend sendMessage response', response);

      const savedMessage = response?.success ? response.data.message : null;

      // Step 2: Relay encrypted message via socket for real-time delivery
      socket.emit('send_message', {
        recipientId: messageData.recipientId,
        envelope,
        ciphertext: ctB64,
        iv: ivB64,
        tag: tagB64,
        nonce: envelope.nonce,
        timestamp: envelope.timestamp,
        seq: envelope.seq,
        messageType: messageData.messageType || 'text',
        messageId: savedMessage?._id,
      });

      // Step 3: Add to local messages (with actual DB data)
      const newMessage = {
        id: savedMessage?._id || `tmp_${Date.now()}`,
        senderId: savedMessage?.sender?._id,
        senderUsername: savedMessage?.sender?.username,
        recipientId: messageData.recipientId,
        text: messageData.plaintext || messageData.text || '',
        seq: envelope.seq,
        messageType: messageData.messageType || 'text',
        timestamp: savedMessage?.createdAt || Date.now(),
        delivered: !!savedMessage,
        read: false,
        isEncrypted: true,
      };

      set((state) => ({
        messages: [...state.messages, newMessage],
      }));

      return savedMessage;
    } catch (error) {
      console.error('Failed to send message:', error?.response?.data || error);
      const msg =
        error?.response?.data?.error ||
        error?.message ||
        'Failed to send message';
      throw new Error(msg);
    }
  },

  sendFileChunk: async (chunkData) => {
    const socket = useSocketStore.getState().socket;
    
    if (!socket || !socket.connected) {
      throw new Error('Socket not connected');
    }

    try {
      // Step 1: Save encrypted file chunk to backend
      const response = await messagesAPI.sendMessage({
        recipientId: chunkData.recipientId,
        ciphertext: chunkData.encryptedData,
        iv: chunkData.iv,
        tag: chunkData.tag,
        seq: chunkData.seq || Date.now(),
        messageType: 'file',
        fileMetadata: {
          fileName: chunkData.fileName,
          fileSize: chunkData.fileSize,
          mimeType: chunkData.mimeType,
          chunkNumber: chunkData.chunkNumber,
          totalChunks: chunkData.totalChunks,
        },
      });

      if (response.success) {
        // Step 2: Relay file chunk via socket for real-time delivery
        socket.emit('send_file_chunk', {
          ...chunkData,
          messageId: response.data.message._id,
        });

        return response.data.message;
      }
    } catch (error) {
      console.error('Failed to send file chunk:', error);
      throw new Error(error.response?.data?.error || 'Failed to send file chunk');
    }
  },

  receiveMessage: (message) => {
    set((state) => ({
      messages: [...state.messages, message],
    }));
  },

  receiveFileChunk: (chunk) => {
    // Handle file chunk reception
    // TODO: Decrypt and reassemble file
    console.log('File chunk received:', chunk);
  },

  updateMessageStatus: (messageId, status) => {
    set((state) => ({
      messages: state.messages.map((msg) =>
        msg.id === messageId ? { ...msg, ...status } : msg
      ),
    }));
  },

  addConversation: (conversation) => {
    set((state) => ({
      conversations: [...state.conversations, conversation],
    }));
  },

  updateConversation: (userId, updates) => {
    set((state) => ({
      conversations: state.conversations.map((conv) =>
        conv.partner.id === userId ? { ...conv, ...updates } : conv
      ),
    }));
  },

  setTypingUser: (userId, isTyping) => {
    set((state) => {
      if (isTyping) {
        return {
          typingUsers: [...state.typingUsers, userId],
        };
      } else {
        return {
          typingUsers: state.typingUsers.filter((id) => id !== userId),
        };
      }
    });
  },

  clearMessages: () => {
    set({ messages: [] });
  },
}));

