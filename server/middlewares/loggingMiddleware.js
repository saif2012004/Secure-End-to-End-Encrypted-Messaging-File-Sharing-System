import Log from '../models/Log.js';
import { logger } from '../utils/logger.js';

/**
 * Middleware to log HTTP requests
 */
export const requestLogger = (req, res, next) => {
  const start = Date.now();

  // Log after response is sent
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logMessage = `${req.method} ${req.originalUrl} ${res.statusCode} - ${duration}ms`;

    // Log to console
    if (res.statusCode >= 400) {
      logger.warn(logMessage);
    } else {
      logger.http(logMessage);
    }
  });

  next();
};

/**
 * Middleware to log errors
 */
export const errorLogger = async (err, req, res, next) => {
  logger.error(`Error: ${err.message}`);
  logger.error(`Stack: ${err.stack}`);

  // Log to database
  try {
    await Log.createLog({
      eventType: 'ERROR',
      level: 'error',
      user: req.user?.id || null,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      success: false,
      message: err.message,
      error: {
        message: err.message,
        stack: err.stack,
        code: err.code,
      },
      details: {
        method: req.method,
        path: req.originalUrl,
        body: req.body,
      },
    });
  } catch (logError) {
    logger.error(`Failed to log error to database: ${logError.message}`);
  }

  // Send error response
  res.status(err.statusCode || 500).json({
    success: false,
    error: err.message || 'Internal server error',
  });
};

/**
 * Middleware to log rate limit exceeded events
 */
export const rateLimitLogger = async (req, res) => {
  try {
    await Log.createLog({
      eventType: 'RATE_LIMIT_EXCEEDED',
      level: 'warn',
      user: req.user?.id || null,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      success: false,
      message: 'Rate limit exceeded',
      details: {
        path: req.originalUrl,
        method: req.method,
      },
    });
  } catch (error) {
    logger.error(`Failed to log rate limit event: ${error.message}`);
  }
};

export default {
  requestLogger,
  errorLogger,
  rateLimitLogger,
};

