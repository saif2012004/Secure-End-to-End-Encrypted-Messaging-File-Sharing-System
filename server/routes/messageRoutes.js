import express from 'express';
import {
  sendMessage,
  getConversation,
  getConversations,
  markAsDelivered,
  markAsRead,
  deleteMessage,
} from '../controllers/messageController.js';
import { protect } from '../middlewares/authMiddleware.js';
import {
  validateSendMessage,
  validateObjectId,
} from '../middlewares/validationMiddleware.js';
import { messageLimiter } from '../config/rateLimitConfig.js';

const router = express.Router();

// All message routes are protected
router.use(protect);

// Message operations
router.post('/send', messageLimiter, validateSendMessage, sendMessage);
router.get('/conversations', getConversations);
router.get('/conversation/:userId', validateObjectId, getConversation);
router.patch('/:messageId/delivered', validateObjectId, markAsDelivered);
router.patch('/:messageId/read', validateObjectId, markAsRead);
router.delete('/:messageId', validateObjectId, deleteMessage);

export default router;

