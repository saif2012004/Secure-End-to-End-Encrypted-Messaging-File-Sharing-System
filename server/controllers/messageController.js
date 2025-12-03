import Message from '../models/Message.js';
import Log from '../models/Log.js';
import User from '../models/User.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';

/**
 * Send a message (store encrypted message metadata)
 * @route POST /api/messages/send
 */
export const sendMessage = async (req, res) => {
  try {
    let {
      recipientId,
      ciphertext,
      iv,
      tag,
      seq,
      signature,
      messageType,
      envelope,
      payload,
      nonce,
      timestamp,
    } = req.body;

    // If an envelope is provided (new client), unpack to legacy fields so backend stays happy.
    if ((!ciphertext || !iv || !tag) && (envelope || payload)) {
      try {
        const env = envelope || {};
        const payloadB64 = payload || env.payload;
        const buf = Buffer.from(payloadB64, 'base64');
        const TAG_LEN = 16;
        const IV_LEN = 12;
        const tagStart = buf.length - TAG_LEN;
        const ivStart = tagStart - IV_LEN;
        ciphertext = ciphertext || buf.slice(0, ivStart).toString('base64');
        iv = iv || buf.slice(ivStart, tagStart).toString('base64');
        tag = tag || buf.slice(tagStart).toString('base64');
        seq = seq ?? env.seq;
        nonce = nonce || env.nonce;
        timestamp = timestamp || env.timestamp;
        messageType = messageType || env.messageType;
        payload = payload || env.payload;
      } catch (e) {
        return res.status(400).json({ success: false, error: 'Invalid envelope format' });
      }
    }

    // Validate required fields
    if (!recipientId || !ciphertext || !iv || !tag || seq === undefined) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: recipientId, ciphertext, iv, tag, seq',
      });
    }

    // Validate recipient ID
    if (!isValidObjectId(recipientId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid recipient ID',
      });
    }

    // Check if recipient exists
    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({
        success: false,
        error: 'Recipient not found',
      });
    }

    // Prevent sending message to self
    if (recipientId === req.user.id) {
      return res.status(400).json({
        success: false,
        error: 'Cannot send message to yourself',
      });
    }

    // Check for replay attack (duplicate sequence number)
    const existingMessage = await Message.findOne({
      sender: req.user.id,
      recipient: recipientId,
      seq,
    });

    if (existingMessage) {
      await Log.createLog({
        eventType: 'REPLAY_DETECTED',
        level: 'warn',
        user: req.user.id,
        ipAddress: req.ip,
        success: false,
        message: 'Potential replay attack detected',
        details: {
          sender: req.user.id,
          recipient: recipientId,
          seq,
        },
      });

      return res.status(409).json({
        success: false,
        error: 'Duplicate sequence number detected (possible replay attack)',
      });
    }

    // Create message
    const message = await Message.create({
      sender: req.user.id,
      recipient: recipientId,
      ciphertext,
      iv,
      tag,
      seq,
      payload: payload || null,
      nonce: nonce || null,
      timestamp: timestamp || Date.now(),
      signature: signature || null,
      messageType: messageType || 'text',
    });

    // Populate sender and recipient data
    await message.populate('sender', 'username email publicKey');
    await message.populate('recipient', 'username email publicKey');

    // Log message sent
    await Log.createLog({
      eventType: 'MESSAGE_SENT',
      level: 'info',
      user: req.user.id,
      ipAddress: req.ip,
      success: true,
      message: `Message sent from ${req.user.id} to ${recipientId}`,
      details: {
        messageId: message._id,
        seq,
        messageType: message.messageType,
      },
    });

    logger.info(`Message sent: ${message._id}`);

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      data: {
        message,
      },
    });
  } catch (error) {
    logger.error(`Send message error: ${error.message}`);

    await Log.createLog({
      eventType: 'MESSAGE_SENT',
      level: 'error',
      user: req.user.id,
      ipAddress: req.ip,
      success: false,
      message: 'Failed to send message',
      error: {
        message: error.message,
      },
    });

    res.status(500).json({
      success: false,
      error: 'Failed to send message',
    });
  }
};

/**
 * Get conversation between current user and another user
 * @route GET /api/messages/conversation/:userId
 */
export const getConversation = async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 50, skip = 0 } = req.query;

    if (!isValidObjectId(userId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid user ID',
      });
    }

    const messages = await Message.find({
      $or: [
        { sender: req.user.id, recipient: userId },
        { sender: userId, recipient: req.user.id },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .populate('sender', 'username email publicKey')
      .populate('recipient', 'username email publicKey');

    res.status(200).json({
      success: true,
      data: {
        messages: messages.reverse(), // Return in chronological order
        count: messages.length,
      },
    });
  } catch (error) {
    logger.error(`Get conversation error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve conversation',
    });
  }
};

/**
 * Get all conversations for current user
 * @route GET /api/messages/conversations
 */
export const getConversations = async (req, res) => {
  try {
    // Get all unique users the current user has conversed with
    const messages = await Message.find({
      $or: [{ sender: req.user.id }, { recipient: req.user.id }],
    })
      .sort({ createdAt: -1 })
      .populate('sender', 'username email publicKey isOnline lastSeen')
      .populate('recipient', 'username email publicKey isOnline lastSeen');

    // Group by conversation partner
    const conversationsMap = new Map();

    messages.forEach((message) => {
      const partnerId =
        message.sender._id.toString() === req.user.id
          ? message.recipient._id.toString()
          : message.sender._id.toString();

      if (!conversationsMap.has(partnerId)) {
        conversationsMap.set(partnerId, {
          partner:
            message.sender._id.toString() === req.user.id
              ? message.recipient
              : message.sender,
          lastMessage: message,
          unreadCount: 0,
        });
      }

      // Count unread messages (messages sent to current user that are not read)
      if (
        message.recipient._id.toString() === req.user.id &&
        !message.read
      ) {
        conversationsMap.get(partnerId).unreadCount++;
      }
    });

    const conversations = Array.from(conversationsMap.values());

    res.status(200).json({
      success: true,
      data: {
        conversations,
      },
    });
  } catch (error) {
    logger.error(`Get conversations error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to retrieve conversations',
    });
  }
};

/**
 * Mark message as delivered
 * @route PATCH /api/messages/:messageId/delivered
 */
export const markAsDelivered = async (req, res) => {
  try {
    const { messageId } = req.params;

    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    // Only recipient can mark as delivered
    if (message.recipient.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    message.delivered = true;
    message.deliveredAt = new Date();
    await message.save();

    await Log.createLog({
      eventType: 'MESSAGE_DELIVERED',
      level: 'info',
      user: req.user.id,
      success: true,
      message: `Message delivered: ${messageId}`,
      details: { messageId },
    });

    res.status(200).json({
      success: true,
      message: 'Message marked as delivered',
    });
  } catch (error) {
    logger.error(`Mark as delivered error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to mark message as delivered',
    });
  }
};

/**
 * Mark message as read
 * @route PATCH /api/messages/:messageId/read
 */
export const markAsRead = async (req, res) => {
  try {
    const { messageId } = req.params;

    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    // Only recipient can mark as read
    if (message.recipient.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    message.read = true;
    message.readAt = new Date();
    await message.save();

    res.status(200).json({
      success: true,
      message: 'Message marked as read',
    });
  } catch (error) {
    logger.error(`Mark as read error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to mark message as read',
    });
  }
};

/**
 * Delete a message
 * @route DELETE /api/messages/:messageId
 */
export const deleteMessage = async (req, res) => {
  try {
    const { messageId } = req.params;

    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    const message = await Message.findById(messageId);

    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    // Only sender can delete their message
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    await message.deleteOne();

    logger.info(`Message deleted: ${messageId}`);

    res.status(200).json({
      success: true,
      message: 'Message deleted successfully',
    });
  } catch (error) {
    logger.error(`Delete message error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to delete message',
    });
  }
};

export default {
  sendMessage,
  getConversation,
  getConversations,
  markAsDelivered,
  markAsRead,
  deleteMessage,
};

