import { verifyToken } from '../utils/jwtUtils.js';
import User from '../models/User.js';
import Log from '../models/Log.js';
import { logger } from '../utils/logger.js';

/**
 * Protect routes - Verify JWT token
 */
export const protect = async (req, res, next) => {
  try {
    let token;

    // Check for token in Authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      await Log.createLog({
        eventType: 'UNAUTHORIZED_ACCESS',
        level: 'warn',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'No token provided',
        details: { path: req.originalUrl },
      });

      return res.status(401).json({
        success: false,
        error: 'Not authorized to access this route',
      });
    }

    try {
      // Verify token
      const decoded = verifyToken(token);

      // Get user from token
      const user = await User.findById(decoded.id);

      if (!user) {
        await Log.createLog({
          eventType: 'UNAUTHORIZED_ACCESS',
          level: 'warn',
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          success: false,
          message: 'User not found for token',
          details: { userId: decoded.id, path: req.originalUrl },
        });

        return res.status(401).json({
          success: false,
          error: 'User not found',
        });
      }

      // Attach user to request
      req.user = {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
      };

      next();
    } catch (error) {
      await Log.createLog({
        eventType: 'UNAUTHORIZED_ACCESS',
        level: 'warn',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Invalid token',
        details: { error: error.message, path: req.originalUrl },
      });

      return res.status(401).json({
        success: false,
        error: 'Not authorized to access this route',
      });
    }
  } catch (error) {
    logger.error(`Auth middleware error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Authentication failed',
    });
  }
};

export default protect;

