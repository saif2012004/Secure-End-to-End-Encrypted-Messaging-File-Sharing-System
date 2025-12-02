import { create } from 'zustand';
import { useSocketStore } from './socketStore';
import { messagesAPI } from '../services/api';
import { decryptMessage } from '../utils/crypto';

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
    
    // Fetch existing messages from backend
    await get().fetchMessages(user.id);
  },

  fetchMessages: async (userId) => {
    try {
      set({ isLoadingMessages: true, messagesError: null });
      
      const response = await messagesAPI.getConversation(userId, 50, 0);
      
      if (response.success) {
        // Decrypt messages for display
        const decryptedMessages = await Promise.all(
          response.data.messages.map(async (msg) => {
            try {
              // NOTE: Placeholder decryption - Members 1 & 2 will implement
              const decrypted = await decryptMessage(
                msg.ciphertext,
                msg.iv,
                msg.tag
              );

              return {
                id: msg._id,
                senderId: msg.sender._id,
                senderUsername: msg.sender.username,
                recipientId: msg.recipient._id,
                text: decrypted, // Decrypted text for display
                ciphertext: msg.ciphertext, // Keep original for verification
                iv: msg.iv,
                tag: msg.tag,
                seq: msg.seq,
                messageType: msg.messageType || 'text',
                timestamp: msg.createdAt,
                delivered: msg.delivered,
                read: msg.read,
                isEncrypted: true,
              };
            } catch (error) {
              console.error('Failed to decrypt message:', error);
              // Show as encrypted if decryption fails
              return {
                id: msg._id,
                senderId: msg.sender._id,
                senderUsername: msg.sender.username,
                recipientId: msg.recipient._id,
                text: '[🔒 Encrypted Message]',
                messageType: msg.messageType || 'text',
                timestamp: msg.createdAt,
                delivered: msg.delivered,
                read: msg.read,
                isEncrypted: true,
                decryptionFailed: true,
              };
            }
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
      // Step 1: Save encrypted message to backend (permanent storage)
      const response = await messagesAPI.sendMessage({
        recipientId: messageData.recipientId,
        ciphertext: messageData.ciphertext,
        iv: messageData.iv,
        tag: messageData.tag,
        seq: messageData.seq,
        signature: messageData.signature,
        messageType: messageData.messageType || 'text',
      });

      if (response.success) {
        const savedMessage = response.data.message;

        // Step 2: Relay encrypted message via socket for real-time delivery
        socket.emit('send_message', {
          recipientId: messageData.recipientId,
          ciphertext: messageData.ciphertext,
          iv: messageData.iv,
          tag: messageData.tag,
          seq: messageData.seq,
          signature: messageData.signature,
          messageType: messageData.messageType || 'text',
          messageId: savedMessage._id, // Include DB message ID
        });

        // Step 3: Add to local messages (with actual DB data)
        const newMessage = {
          id: savedMessage._id,
          senderId: savedMessage.sender._id,
          senderUsername: savedMessage.sender.username,
          recipientId: messageData.recipientId,
          text: messageData.plaintext, // For display only (already decrypted)
          ciphertext: messageData.ciphertext,
          iv: messageData.iv,
          tag: messageData.tag,
          seq: messageData.seq,
          messageType: messageData.messageType || 'text',
          timestamp: savedMessage.createdAt,
          delivered: false,
          read: false,
          isEncrypted: true,
        };

        set((state) => ({
          messages: [...state.messages, newMessage],
        }));

        return savedMessage;
      }
    } catch (error) {
      console.error('Failed to send message:', error);
      throw new Error(error.response?.data?.error || 'Failed to send message');
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

