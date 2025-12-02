import { body, param, query, validationResult } from 'express-validator';

/**
 * Middleware to handle validation errors
 */
export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array(),
    });
  }

  next();
};

/**
 * Validation rules for user registration
 */
export const validateRegister = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores and hyphens'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long'),
  handleValidationErrors,
];

/**
 * Validation rules for user login
 */
export const validateLogin = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors,
];

/**
 * Validation rules for sending messages
 */
export const validateSendMessage = [
  body('recipientId')
    .notEmpty()
    .withMessage('Recipient ID is required')
    .isMongoId()
    .withMessage('Invalid recipient ID'),
  body('ciphertext')
    .notEmpty()
    .withMessage('Ciphertext is required')
    .isString()
    .withMessage('Ciphertext must be a string'),
  body('iv')
    .notEmpty()
    .withMessage('IV is required')
    .isString()
    .withMessage('IV must be a string'),
  body('tag')
    .notEmpty()
    .withMessage('Tag is required')
    .isString()
    .withMessage('Tag must be a string'),
  body('seq')
    .notEmpty()
    .withMessage('Sequence number is required')
    .isNumeric()
    .withMessage('Sequence number must be numeric'),
  body('messageType')
    .optional()
    .isIn(['text', 'file', 'system'])
    .withMessage('Invalid message type'),
  handleValidationErrors,
];

/**
 * Validation rules for file chunk upload
 */
export const validateFileChunk = [
  body('messageId')
    .notEmpty()
    .withMessage('Message ID is required')
    .isMongoId()
    .withMessage('Invalid message ID'),
  body('chunkNumber')
    .notEmpty()
    .withMessage('Chunk number is required')
    .isNumeric()
    .withMessage('Chunk number must be numeric'),
  body('totalChunks')
    .notEmpty()
    .withMessage('Total chunks is required')
    .isNumeric()
    .withMessage('Total chunks must be numeric'),
  body('encryptedData')
    .notEmpty()
    .withMessage('Encrypted data is required')
    .isString()
    .withMessage('Encrypted data must be a string'),
  body('iv')
    .notEmpty()
    .withMessage('IV is required'),
  body('tag')
    .notEmpty()
    .withMessage('Tag is required'),
  body('size')
    .notEmpty()
    .withMessage('Size is required')
    .isNumeric()
    .withMessage('Size must be numeric'),
  body('hash')
    .notEmpty()
    .withMessage('Hash is required')
    .isString()
    .withMessage('Hash must be a string'),
  handleValidationErrors,
];

/**
 * Validation rules for MongoDB ObjectId params
 */
export const validateObjectId = [
  param('id')
    .optional()
    .isMongoId()
    .withMessage('Invalid ID format'),
  param('userId')
    .optional()
    .isMongoId()
    .withMessage('Invalid user ID format'),
  param('messageId')
    .optional()
    .isMongoId()
    .withMessage('Invalid message ID format'),
  handleValidationErrors,
];

/**
 * Validation rules for search query
 */
export const validateSearch = [
  query('query')
    .trim()
    .notEmpty()
    .withMessage('Search query is required')
    .isLength({ min: 2, max: 50 })
    .withMessage('Search query must be between 2 and 50 characters'),
  handleValidationErrors,
];

export default {
  handleValidationErrors,
  validateRegister,
  validateLogin,
  validateSendMessage,
  validateFileChunk,
  validateObjectId,
  validateSearch,
};

