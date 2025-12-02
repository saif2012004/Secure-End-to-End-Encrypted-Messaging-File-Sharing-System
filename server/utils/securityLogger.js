import Log from '../models/Log.js';
import { logger } from './logger.js';

/**
 * Security Logger Utility
 * Following OWASP Logging Cheat Sheet recommendations
 * https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
 * 
 * IMPORTANT: This logger NEVER logs:
 * - Plaintext messages
 * - Encryption keys
 * - Passwords
 * - Session tokens
 * - Personal identifiable information (PII) beyond usernames
 * - Encrypted content (ciphertext, IV, tags)
 */

/**
 * Extract safe request metadata (no sensitive data)
 * @param {object} req - Express request object
 * @returns {object} Safe metadata
 */
const extractSafeMetadata = (req) => {
  // Extract IP (handle proxy scenarios)
  const ipAddress = 
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip;

  return {
    ipAddress,
    userAgent: req.get('user-agent') || 'Unknown',
    method: req.method,
    path: req.originalUrl || req.url,
    headers: {
      contentType: req.get('content-type'),
      origin: req.get('origin'),
      referer: req.get('referer'),
      // NOTE: NO Authorization header logged
    },
    query: sanitizeObject(req.query),
    params: sanitizeObject(req.params),
  };
};

/**
 * Sanitize object to remove sensitive fields
 * @param {object} obj - Object to sanitize
 * @returns {object} Sanitized object
 */
const sanitizeObject = (obj) => {
  if (!obj || typeof obj !== 'object') return obj;

  const sanitized = { ...obj };
  
  // Remove sensitive fields
  const sensitiveFields = [
    'password',
    'token',
    'secret',
    'key',
    'authorization',
    'ciphertext',
    'iv',
    'tag',
    'privateKey',
    'sessionId',
    'cookie',
  ];

  for (const field of sensitiveFields) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }

  return sanitized;
};

/**
 * Log authentication success
 */
export const logAuthSuccess = async (req, user) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'AUTH_LOGIN_SUCCESS',
    level: 'info',
    user: user._id,
    username: user.username,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: true,
    message: `User ${user.username} logged in successfully`,
    details: {
      timestamp: new Date().toISOString(),
    },
  });

  logger.info(`[AUTH] Login success: ${user.username} from ${metadata.ipAddress}`);
};

/**
 * Log authentication failure
 */
export const logAuthFailure = async (req, username, reason) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'AUTH_LOGIN_FAILURE',
    level: 'warn',
    username,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: false,
    message: `Login attempt failed: ${reason}`,
    details: {
      reason,
      timestamp: new Date().toISOString(),
    },
  });

  logger.warn(`[AUTH] Login failed: ${username} from ${metadata.ipAddress} - ${reason}`);
};

/**
 * Log user registration
 */
export const logRegistration = async (req, user) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'AUTH_REGISTER',
    level: 'info',
    user: user._id,
    username: user.username,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: true,
    message: `New user registered: ${user.username}`,
    details: {
      timestamp: new Date().toISOString(),
    },
  });

  logger.info(`[AUTH] Registration: ${user.username} from ${metadata.ipAddress}`);
};

/**
 * Log message relay event (METADATA ONLY - NO CONTENT)
 */
export const logMessageRelay = async (req, senderId, recipientId, metadata = {}) => {
  const requestMeta = req ? extractSafeMetadata(req) : {};
  
  await Log.createLog({
    eventType: 'MESSAGE_SENT',
    level: 'info',
    user: senderId,
    userFrom: senderId,
    userTo: recipientId,
    ipAddress: requestMeta.ipAddress,
    userAgent: requestMeta.userAgent,
    success: true,
    message: 'Encrypted message relayed',
    details: {
      seq: metadata.seq,
      messageType: metadata.messageType || 'text',
      timestamp: new Date().toISOString(),
      // NOTE: NO ciphertext, iv, tag, or content logged!
    },
  });

  logger.info(`[MESSAGE] Relayed from ${senderId} to ${recipientId}`);
};

/**
 * Log file chunk upload event (METADATA ONLY - NO CONTENT)
 */
export const logFileChunkUpload = async (req, senderId, recipientId, metadata = {}) => {
  const requestMeta = req ? extractSafeMetadata(req) : {};
  
  await Log.createLog({
    eventType: 'FILE_UPLOAD_CHUNK',
    level: 'info',
    user: senderId,
    userFrom: senderId,
    userTo: recipientId,
    ipAddress: requestMeta.ipAddress,
    userAgent: requestMeta.userAgent,
    success: true,
    message: 'Encrypted file chunk uploaded',
    details: {
      fileName: metadata.fileName,
      fileSize: metadata.fileSize,
      mimeType: metadata.mimeType,
      chunkNumber: metadata.chunkNumber,
      totalChunks: metadata.totalChunks,
      timestamp: new Date().toISOString(),
      // NOTE: NO encrypted data logged!
    },
  });

  logger.info(
    `[FILE] Chunk ${metadata.chunkNumber + 1}/${metadata.totalChunks} ` +
    `from ${senderId} to ${recipientId}`
  );
};

/**
 * Log unauthorized access attempt
 */
export const logUnauthorizedAccess = async (req, reason) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'UNAUTHORIZED_ACCESS',
    level: 'warn',
    user: req.user?.id || null,
    username: req.user?.username || null,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: false,
    message: `Unauthorized access attempt: ${reason}`,
    details: {
      reason,
      timestamp: new Date().toISOString(),
    },
  });

  logger.warn(`[SECURITY] Unauthorized access: ${metadata.path} from ${metadata.ipAddress}`);
};

/**
 * Log replay attack detection
 */
export const logReplayDetection = async (req, senderId, recipientId, seq) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'REPLAY_DETECTED',
    level: 'error',
    user: senderId,
    userFrom: senderId,
    userTo: recipientId,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    success: false,
    message: 'Potential replay attack detected',
    details: {
      seq,
      reason: 'Duplicate sequence number',
      timestamp: new Date().toISOString(),
    },
  });

  logger.error(
    `[SECURITY] REPLAY ATTACK detected: ${senderId} → ${recipientId}, seq: ${seq}`
  );
};

/**
 * Log invalid signature detection
 */
export const logInvalidSignature = async (req, senderId, recipientId) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'INVALID_SIGNATURE',
    level: 'error',
    user: senderId,
    userFrom: senderId,
    userTo: recipientId,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    success: false,
    message: 'Invalid digital signature detected',
    details: {
      timestamp: new Date().toISOString(),
    },
  });

  logger.error(`[SECURITY] Invalid signature: ${senderId} → ${recipientId}`);
};

/**
 * Log metadata access (for auditing who accessed what)
 */
export const logMetadataAccess = async (req, resourceType, resourceId) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'METADATA_ACCESS',
    level: 'info',
    user: req.user?.id || null,
    username: req.user?.username || null,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: true,
    message: `Metadata accessed: ${resourceType}`,
    details: {
      resourceType,
      resourceId,
      timestamp: new Date().toISOString(),
    },
  });

  logger.info(`[ACCESS] ${req.user?.username} accessed ${resourceType}:${resourceId}`);
};

/**
 * Log abnormal request (potential attack)
 */
export const logAbnormalRequest = async (req, reason) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'ABNORMAL_REQUEST',
    level: 'warn',
    user: req.user?.id || null,
    username: req.user?.username || null,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: false,
    message: `Abnormal request detected: ${reason}`,
    details: {
      reason,
      timestamp: new Date().toISOString(),
      requestSize: req.get('content-length'),
    },
  });

  logger.warn(`[SECURITY] Abnormal request from ${metadata.ipAddress}: ${reason}`);
};

/**
 * Log suspicious activity
 */
export const logSuspiciousActivity = async (req, activityType, details = {}) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'SUSPICIOUS_ACTIVITY',
    level: 'error',
    user: req.user?.id || null,
    username: req.user?.username || null,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: false,
    message: `Suspicious activity: ${activityType}`,
    details: {
      activityType,
      ...details,
      timestamp: new Date().toISOString(),
    },
  });

  logger.error(`[SECURITY] Suspicious activity: ${activityType} from ${metadata.ipAddress}`);
};

/**
 * Log key exchange relay
 */
export const logKeyExchange = async (req, senderId, recipientId) => {
  const metadata = req ? extractSafeMetadata(req) : {};
  
  await Log.createLog({
    eventType: 'KEY_EXCHANGE_RELAY',
    level: 'info',
    user: senderId,
    userFrom: senderId,
    userTo: recipientId,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    success: true,
    message: 'Public key exchange relayed',
    details: {
      timestamp: new Date().toISOString(),
      // NOTE: NO private keys logged!
    },
  });

  logger.info(`[CRYPTO] Key exchange: ${senderId} → ${recipientId}`);
};

/**
 * Log rate limit exceeded
 */
export const logRateLimitExceeded = async (req) => {
  const metadata = extractSafeMetadata(req);
  
  await Log.createLog({
    eventType: 'RATE_LIMIT_EXCEEDED',
    level: 'warn',
    user: req.user?.id || null,
    username: req.user?.username || null,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: false,
    message: 'Rate limit exceeded',
    details: {
      timestamp: new Date().toISOString(),
    },
  });

  logger.warn(`[RATE_LIMIT] Exceeded from ${metadata.ipAddress} on ${metadata.path}`);
};

/**
 * Generic security event logger
 */
export const logSecurityEvent = async (eventType, level, req, message, details = {}) => {
  const metadata = req ? extractSafeMetadata(req) : {};
  
  await Log.createLog({
    eventType,
    level,
    user: req?.user?.id || null,
    username: req?.user?.username || null,
    ipAddress: metadata.ipAddress,
    userAgent: metadata.userAgent,
    method: metadata.method,
    path: metadata.path,
    success: details.success !== false,
    message,
    details: {
      ...sanitizeObject(details),
      timestamp: new Date().toISOString(),
    },
  });

  logger.info(`[SECURITY] ${eventType}: ${message}`);
};

export default {
  logAuthSuccess,
  logAuthFailure,
  logRegistration,
  logMessageRelay,
  logFileChunkUpload,
  logUnauthorizedAccess,
  logReplayDetection,
  logInvalidSignature,
  logMetadataAccess,
  logAbnormalRequest,
  logSuspiciousActivity,
  logKeyExchange,
  logRateLimitExceeded,
  logSecurityEvent,
};

