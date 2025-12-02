import { Server } from 'socket.io';
import { verifyToken } from '../utils/jwtUtils.js';
import User from '../models/User.js';
import Message from '../models/Message.js';
import FileChunk from '../models/FileChunk.js';
import Log from '../models/Log.js';
import { logger } from '../utils/logger.js';

/**
 * Initialize Socket.io for real-time messaging
 * This server acts as a RELAY ONLY - it does not perform any encryption/decryption
 * All cryptographic operations are handled client-side
 * 
 * @param {object} server - HTTP server instance
 * @returns {object} Socket.io server instance
 */
export const initializeSocket = (server) => {
  const io = new Server(server, {
    cors: {
      origin: process.env.SOCKET_CORS_ORIGIN || 'http://localhost:3000',
      credentials: true,
      methods: ['GET', 'POST'],
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    maxHttpBufferSize: 10e6, // 10MB for file chunks
  });

  // Middleware to authenticate socket connections
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token;

      if (!token) {
        return next(new Error('Authentication error: No token provided'));
      }

      // Verify token
      const decoded = verifyToken(token);

      // Get user
      const user = await User.findById(decoded.id);

      if (!user) {
        return next(new Error('Authentication error: User not found'));
      }

      // Attach user to socket
      socket.userId = user._id.toString();
      socket.username = user.username;

      next();
    } catch (error) {
      logger.error(`Socket authentication error: ${error.message}`);
      next(new Error('Authentication error'));
    }
  });

  // Handle socket connections
  io.on('connection', async (socket) => {
    logger.info(`User connected: ${socket.username} (${socket.userId})`);

    try {
      // Update user status to online
      await User.findByIdAndUpdate(socket.userId, {
        isOnline: true,
        socketId: socket.id,
        lastSeen: new Date(),
      });

      // Log connection
      await Log.createLog({
        eventType: 'SOCKET_CONNECT',
        level: 'info',
        user: socket.userId,
        sessionId: socket.id,
        success: true,
        message: `User connected: ${socket.username}`,
      });

      // Notify user's contacts that they're online
      socket.broadcast.emit('user:online', {
        userId: socket.userId,
        username: socket.username,
      });

      // Join user to their own room for private messaging
      socket.join(socket.userId);

      /**
       * Handle explicit room joining for 1-1 chat
       * Room format: sorted user IDs joined by underscore
       * Example: "userId1_userId2"
       */
      socket.on('join_room', async (data) => {
        try {
          const { recipientId } = data;

          if (!recipientId) {
            socket.emit('room:error', { error: 'Recipient ID required' });
            return;
          }

          // Create room name from sorted user IDs for consistency
          const roomName = [socket.userId, recipientId].sort().join('_');

          // Join the room
          socket.join(roomName);

          logger.info(`User ${socket.userId} joined room: ${roomName}`);

          // Log room join
          await Log.createLog({
            eventType: 'SOCKET_CONNECT',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: `User joined chat room`,
            details: {
              roomName,
              recipientId,
            },
          });

          // Acknowledge
          socket.emit('room:joined', {
            roomName,
            recipientId,
            success: true,
          });

          // Notify recipient that user is ready to chat
          io.to(recipientId).emit('room:user-ready', {
            userId: socket.userId,
            username: socket.username,
            roomName,
          });
        } catch (error) {
          logger.error(`Room join error: ${error.message}`);
          socket.emit('room:error', {
            error: 'Failed to join room',
          });

          await Log.createLog({
            eventType: 'ERROR',
            level: 'error',
            user: socket.userId,
            sessionId: socket.id,
            success: false,
            message: 'Failed to join chat room',
            error: {
              message: error.message,
            },
          });
        }
      });

      /**
       * Handle leaving a chat room
       */
      socket.on('leave_room', async (data) => {
        try {
          const { recipientId } = data;

          if (!recipientId) {
            socket.emit('room:error', { error: 'Recipient ID required' });
            return;
          }

          const roomName = [socket.userId, recipientId].sort().join('_');
          socket.leave(roomName);

          logger.info(`User ${socket.userId} left room: ${roomName}`);

          await Log.createLog({
            eventType: 'SOCKET_DISCONNECT',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: `User left chat room`,
            details: {
              roomName,
              recipientId,
            },
          });

          socket.emit('room:left', {
            roomName,
            success: true,
          });
        } catch (error) {
          logger.error(`Room leave error: ${error.message}`);
          socket.emit('room:error', {
            error: 'Failed to leave room',
          });
        }
      });

      // Handle key exchange relay
      socket.on('key-exchange:send', async (data) => {
        try {
          const { recipientId, publicKey, signature } = data;

          logger.info(`Key exchange from ${socket.userId} to ${recipientId}`);

          // Log key exchange relay
          await Log.createLog({
            eventType: 'KEY_EXCHANGE_RELAY',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: 'Key exchange relayed',
            details: {
              sender: socket.userId,
              recipient: recipientId,
            },
          });

          // Relay to recipient
          io.to(recipientId).emit('key-exchange:receive', {
            senderId: socket.userId,
            senderUsername: socket.username,
            publicKey,
            signature,
          });

          // Acknowledge sender
          socket.emit('key-exchange:sent', {
            recipientId,
            success: true,
          });
        } catch (error) {
          logger.error(`Key exchange error: ${error.message}`);
          socket.emit('key-exchange:error', {
            error: 'Failed to relay key exchange',
          });
        }
      });

      /**
       * Handle real-time message relay
       * Server DOES NOT decrypt - only relays encrypted ciphertext
       */
      socket.on('send_message', async (data) => {
        try {
          const { 
            recipientId, 
            ciphertext, 
            iv, 
            tag, 
            seq,
            signature,
            messageType 
          } = data;

          // Validate required fields
          if (!recipientId || !ciphertext || !iv || !tag || seq === undefined) {
            socket.emit('message:error', {
              error: 'Missing required fields',
            });
            return;
          }

          logger.info(`Message relay from ${socket.userId} to ${recipientId}`);

          // Create room name for targeted delivery
          const roomName = [socket.userId, recipientId].sort().join('_');

          // Relay encrypted message to recipient (NO DECRYPTION)
          io.to(recipientId).emit('receive_message', {
            senderId: socket.userId,
            senderUsername: socket.username,
            ciphertext,      // Encrypted data - server doesn't read this
            iv,              // Initialization vector
            tag,             // Authentication tag
            seq,             // Sequence number
            signature,       // Digital signature (if provided)
            messageType: messageType || 'text',
            timestamp: new Date().toISOString(),
          });

          // Also broadcast to room if both users are in it
          socket.to(roomName).emit('receive_message', {
            senderId: socket.userId,
            senderUsername: socket.username,
            ciphertext,
            iv,
            tag,
            seq,
            signature,
            messageType: messageType || 'text',
            timestamp: new Date().toISOString(),
          });

          // Log message relay (NO message content logged)
          await Log.createLog({
            eventType: 'MESSAGE_SENT',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: 'Encrypted message relayed via socket',
            details: {
              sender: socket.userId,
              recipient: recipientId,
              seq,
              messageType: messageType || 'text',
              // NOTE: We do NOT log ciphertext, iv, or tag
            },
          });

          // Acknowledge sender
          socket.emit('message:sent', {
            recipientId,
            seq,
            success: true,
            timestamp: new Date().toISOString(),
          });
        } catch (error) {
          logger.error(`Message relay error: ${error.message}`);
          
          socket.emit('message:error', {
            error: 'Failed to relay message',
          });

          await Log.createLog({
            eventType: 'ERROR',
            level: 'error',
            user: socket.userId,
            sessionId: socket.id,
            success: false,
            message: 'Message relay failed',
            error: {
              message: error.message,
            },
          });
        }
      });

      /**
       * Handle encrypted file chunk relay
       * Server DOES NOT decrypt - only relays encrypted chunks
       */
      socket.on('send_file_chunk', async (data) => {
        try {
          const {
            recipientId,
            messageId,
            chunkNumber,
            totalChunks,
            encryptedData,  // Encrypted chunk - server doesn't decrypt
            iv,
            tag,
            hash,
            fileName,
            fileSize,
            mimeType,
          } = data;

          // Validate required fields
          if (!recipientId || !encryptedData || !iv || !tag) {
            socket.emit('file:error', {
              error: 'Missing required fields for file chunk',
            });
            return;
          }

          logger.info(
            `File chunk ${chunkNumber + 1}/${totalChunks} relay from ${socket.userId} to ${recipientId}`
          );

          // Relay encrypted chunk to recipient (NO DECRYPTION)
          io.to(recipientId).emit('receive_file_chunk', {
            senderId: socket.userId,
            senderUsername: socket.username,
            messageId,
            chunkNumber,
            totalChunks,
            encryptedData,   // Encrypted - server doesn't read this
            iv,
            tag,
            hash,
            fileName,
            fileSize,
            mimeType,
            timestamp: new Date().toISOString(),
          });

          // Log file chunk relay (NO chunk content logged)
          await Log.createLog({
            eventType: 'FILE_UPLOAD',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: 'Encrypted file chunk relayed via socket',
            details: {
              sender: socket.userId,
              recipient: recipientId,
              messageId,
              chunkNumber,
              totalChunks,
              fileName,
              fileSize,
              mimeType,
              // NOTE: We do NOT log encrypted data
            },
          });

          // Acknowledge sender
          socket.emit('file:chunk-sent', {
            recipientId,
            messageId,
            chunkNumber,
            totalChunks,
            success: true,
          });

          // If this is the last chunk, notify completion
          if (chunkNumber === totalChunks - 1) {
            socket.emit('file:upload-complete', {
              recipientId,
              messageId,
              totalChunks,
            });

            logger.info(`File upload complete: ${fileName} (${totalChunks} chunks)`);
          }
        } catch (error) {
          logger.error(`File chunk relay error: ${error.message}`);
          
          socket.emit('file:error', {
            error: 'Failed to relay file chunk',
          });

          await Log.createLog({
            eventType: 'ERROR',
            level: 'error',
            user: socket.userId,
            sessionId: socket.id,
            success: false,
            message: 'File chunk relay failed',
            error: {
              message: error.message,
            },
          });
        }
      });

      /**
       * Request file download (notify sender to start sending chunks)
       */
      socket.on('request_file', async (data) => {
        try {
          const { senderId, messageId } = data;

          if (!senderId || !messageId) {
            socket.emit('file:error', { error: 'Missing required fields' });
            return;
          }

          // Notify file sender that recipient wants to download
          io.to(senderId).emit('file:requested', {
            requesterId: socket.userId,
            requesterUsername: socket.username,
            messageId,
          });

          await Log.createLog({
            eventType: 'FILE_DOWNLOAD',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: 'File download requested',
            details: {
              messageId,
              senderId,
            },
          });

          socket.emit('file:request-sent', {
            messageId,
            success: true,
          });
        } catch (error) {
          logger.error(`File request error: ${error.message}`);
          socket.emit('file:error', {
            error: 'Failed to request file',
          });
        }
      });

      /**
       * Handle typing indicators
       */
      socket.on('typing:start', async (data) => {
        try {
          const { recipientId } = data;
          
          if (!recipientId) return;

          // Send to recipient and room
          io.to(recipientId).emit('typing:user', {
            userId: socket.userId,
            username: socket.username,
            isTyping: true,
          });

          const roomName = [socket.userId, recipientId].sort().join('_');
          socket.to(roomName).emit('typing:user', {
            userId: socket.userId,
            username: socket.username,
            isTyping: true,
          });
        } catch (error) {
          logger.error(`Typing start error: ${error.message}`);
        }
      });

      socket.on('typing:stop', async (data) => {
        try {
          const { recipientId } = data;
          
          if (!recipientId) return;

          io.to(recipientId).emit('typing:user', {
            userId: socket.userId,
            username: socket.username,
            isTyping: false,
          });

          const roomName = [socket.userId, recipientId].sort().join('_');
          socket.to(roomName).emit('typing:user', {
            userId: socket.userId,
            username: socket.username,
            isTyping: false,
          });
        } catch (error) {
          logger.error(`Typing stop error: ${error.message}`);
        }
      });

      // Handle message delivery confirmation
      socket.on('message:delivered', async (data) => {
        try {
          const { messageId, senderId } = data;

          // Update message status
          await Message.findByIdAndUpdate(messageId, {
            delivered: true,
            deliveredAt: new Date(),
          });

          // Notify sender
          io.to(senderId).emit('message:delivery-confirmed', {
            messageId,
          });
        } catch (error) {
          logger.error(`Delivery confirmation error: ${error.message}`);
        }
      });

      // Handle message read confirmation
      socket.on('message:read', async (data) => {
        try {
          const { messageId, senderId } = data;

          // Update message status
          await Message.findByIdAndUpdate(messageId, {
            read: true,
            readAt: new Date(),
          });

          // Notify sender
          io.to(senderId).emit('message:read-confirmed', {
            messageId,
          });
        } catch (error) {
          logger.error(`Read confirmation error: ${error.message}`);
        }
      });

      // Handle disconnection
      socket.on('disconnect', async () => {
        logger.info(`User disconnected: ${socket.username} (${socket.userId})`);

        try {
          // Update user status to offline
          await User.findByIdAndUpdate(socket.userId, {
            isOnline: false,
            lastSeen: new Date(),
            socketId: null,
          });

          // Log disconnection
          await Log.createLog({
            eventType: 'SOCKET_DISCONNECT',
            level: 'info',
            user: socket.userId,
            sessionId: socket.id,
            success: true,
            message: `User disconnected: ${socket.username}`,
          });

          // Notify user's contacts that they're offline
          socket.broadcast.emit('user:offline', {
            userId: socket.userId,
            username: socket.username,
            lastSeen: new Date(),
          });
        } catch (error) {
          logger.error(`Disconnect handler error: ${error.message}`);
        }
      });

      // Handle errors
      socket.on('error', (error) => {
        logger.error(`Socket error for user ${socket.username}: ${error.message}`);
      });
    } catch (error) {
      logger.error(`Socket connection handler error: ${error.message}`);
    }
  });

  return io;
};

export default initializeSocket;

