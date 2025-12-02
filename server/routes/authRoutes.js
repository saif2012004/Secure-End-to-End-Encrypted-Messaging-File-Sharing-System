import express from 'express';
import {
  register,
  login,
  logout,
  getCurrentUser,
  updatePublicKey,
  getUserById,
  searchUsers,
} from '../controllers/authController.js';
import { protect } from '../middlewares/authMiddleware.js';
import {
  validateRegister,
  validateLogin,
  validateObjectId,
  validateSearch,
} from '../middlewares/validationMiddleware.js';
import { authLimiter } from '../config/rateLimitConfig.js';

const router = express.Router();

// Public routes (with rate limiting)
router.post('/register', authLimiter, validateRegister, register);
router.post('/login', authLimiter, validateLogin, login);

// Protected routes
router.post('/logout', protect, logout);
router.get('/me', protect, getCurrentUser);
router.put('/public-key', protect, updatePublicKey);
router.get('/user/:userId', protect, validateObjectId, getUserById);
router.get('/users/search', protect, validateSearch, searchUsers);

export default router;

