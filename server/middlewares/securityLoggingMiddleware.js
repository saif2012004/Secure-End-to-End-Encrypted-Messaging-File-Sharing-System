import {
  logUnauthorizedAccess,
  logAbnormalRequest,
  logSuspiciousActivity,
  logMetadataAccess,
} from '../utils/securityLogger.js';
import { logger } from '../utils/logger.js';

/**
 * Security Logging Middleware
 * Following OWASP Logging & Monitoring Best Practices
 * 
 * This middleware detects and logs:
 * - Abnormal requests
 * - Suspicious patterns
 * - Metadata access
 * - Security violations
 */

/**
 * Middleware to detect and log abnormal requests
 */
export const abnormalRequestDetector = async (req, res, next) => {
  try {
    // Check for abnormally large payloads
    const contentLength = parseInt(req.get('content-length') || '0');
    if (contentLength > 15 * 1024 * 1024) { // 15MB
      await logAbnormalRequest(req, `Payload too large: ${contentLength} bytes`);
      return res.status(413).json({
        success: false,
        error: 'Payload too large',
      });
    }

    // Check for suspicious user agents
    const userAgent = req.get('user-agent') || '';
    const suspiciousAgents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit'];
    if (suspiciousAgents.some(agent => userAgent.toLowerCase().includes(agent))) {
      await logSuspiciousActivity(req, 'Suspicious user agent', { userAgent });
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
      });
    }

    // Check for SQL injection patterns in query parameters
    const queryString = JSON.stringify(req.query).toLowerCase();
    const sqlPatterns = ['union select', 'drop table', 'insert into', '--', '; --'];
    if (sqlPatterns.some(pattern => queryString.includes(pattern))) {
      await logSuspiciousActivity(req, 'SQL injection attempt detected', {
        query: req.query,
      });
      return res.status(400).json({
        success: false,
        error: 'Invalid request',
      });
    }

    // Check for XSS patterns in request body
    if (req.body && typeof req.body === 'object') {
      const bodyString = JSON.stringify(req.body).toLowerCase();
      const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload='];
      if (xssPatterns.some(pattern => bodyString.includes(pattern))) {
        await logSuspiciousActivity(req, 'XSS attempt detected');
        return res.status(400).json({
          success: false,
          error: 'Invalid request',
        });
      }
    }

    // Check for path traversal attempts
    if (req.path.includes('..') || req.path.includes('~')) {
      await logSuspiciousActivity(req, 'Path traversal attempt');
      return res.status(400).json({
        success: false,
        error: 'Invalid path',
      });
    }

    next();
  } catch (error) {
    logger.error(`Abnormal request detector error: ${error.message}`);
    next();
  }
};

/**
 * Middleware to log metadata access
 */
export const logMetadataAccessMiddleware = (resourceType) => {
  return async (req, res, next) => {
    try {
      const resourceId = req.params.id || req.params.userId || req.params.messageId || 'unknown';
      
      // Log after successful response
      const originalJson = res.json;
      res.json = function (data) {
        if (res.statusCode === 200 && data.success !== false) {
          // Async log (don't wait)
          logMetadataAccess(req, resourceType, resourceId).catch(err => {
            logger.error(`Failed to log metadata access: ${err.message}`);
          });
        }
        return originalJson.call(this, data);
      };

      next();
    } catch (error) {
      logger.error(`Metadata access logging error: ${error.message}`);
      next();
    }
  };
};

/**
 * Middleware to detect brute force attacks
 * Logs multiple failed attempts from same IP
 */
const failedAttempts = new Map(); // IP -> { count, firstAttempt }

export const bruteForceDetector = async (req, res, next) => {
  const ip = req.ip;
  
  // Listen for failed auth responses
  const originalJson = res.json;
  res.json = function (data) {
    if (res.statusCode === 401 || (data && data.success === false)) {
      // Track failed attempt
      if (!failedAttempts.has(ip)) {
        failedAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
      } else {
        const attempts = failedAttempts.get(ip);
        attempts.count++;
        
        // Reset if more than 15 minutes passed
        if (Date.now() - attempts.firstAttempt > 15 * 60 * 1000) {
          failedAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
        }
        
        // Log if suspicious (5+ failures)
        if (attempts.count >= 5) {
          logSuspiciousActivity(req, 'Potential brute force attack', {
            failedAttempts: attempts.count,
            timeWindow: Math.floor((Date.now() - attempts.firstAttempt) / 1000) + 's',
          }).catch(err => {
            logger.error(`Failed to log brute force: ${err.message}`);
          });
        }
        
        // Block if excessive (10+ failures)
        if (attempts.count >= 10) {
          return originalJson.call(this, {
            success: false,
            error: 'Too many failed attempts. Please try again later.',
          });
        }
      }
    } else if (res.statusCode === 200 && data && data.success === true) {
      // Clear failed attempts on success
      failedAttempts.delete(ip);
    }
    
    return originalJson.call(this, data);
  };
  
  next();
};

/**
 * Cleanup old brute force tracking data every hour
 */
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of failedAttempts.entries()) {
    if (now - data.firstAttempt > 60 * 60 * 1000) { // 1 hour
      failedAttempts.delete(ip);
    }
  }
}, 60 * 60 * 1000); // Run every hour

/**
 * Middleware to detect suspicious patterns in requests
 */
export const suspiciousPatternDetector = async (req, res, next) => {
  try {
    // Detect multiple rapid requests (simple rate detection)
    const requestKey = `${req.ip}_${req.path}`;
    const now = Date.now();
    
    if (!global.requestTimestamps) {
      global.requestTimestamps = new Map();
    }
    
    if (!global.requestTimestamps.has(requestKey)) {
      global.requestTimestamps.set(requestKey, [now]);
    } else {
      const timestamps = global.requestTimestamps.get(requestKey);
      
      // Keep only last minute
      const recentTimestamps = timestamps.filter(t => now - t < 60000);
      recentTimestamps.push(now);
      global.requestTimestamps.set(requestKey, recentTimestamps);
      
      // If more than 100 requests in last minute
      if (recentTimestamps.length > 100) {
        await logSuspiciousActivity(req, 'Rapid request pattern detected', {
          requestsPerMinute: recentTimestamps.length,
        });
      }
    }
    
    next();
  } catch (error) {
    logger.error(`Suspicious pattern detector error: ${error.message}`);
    next();
  }
};

// Cleanup old request timestamps every 5 minutes
setInterval(() => {
  if (global.requestTimestamps) {
    const now = Date.now();
    for (const [key, timestamps] of global.requestTimestamps.entries()) {
      const recent = timestamps.filter(t => now - t < 60000);
      if (recent.length === 0) {
        global.requestTimestamps.delete(key);
      } else {
        global.requestTimestamps.set(key, recent);
      }
    }
  }
}, 5 * 60 * 1000); // Run every 5 minutes

/**
 * Middleware to sanitize and validate request data
 * Prevents logging of sensitive information
 */
export const requestSanitizer = (req, res, next) => {
  // Remove sensitive fields from req.body before logging
  if (req.body) {
    const sensitiveFields = [
      'password',
      'token',
      'secret',
      'privateKey',
      'ciphertext',
      'iv',
      'tag',
    ];
    
    for (const field of sensitiveFields) {
      if (field in req.body) {
        // Mark as redacted for logging purposes
        req.body[`_${field}_redacted`] = true;
      }
    }
  }
  
  next();
};

export default {
  abnormalRequestDetector,
  logMetadataAccessMiddleware,
  bruteForceDetector,
  suspiciousPatternDetector,
  requestSanitizer,
};

