import User from '../models/User.js';
import Log from '../models/Log.js';
import { generateToken } from '../utils/jwtUtils.js';
import { validatePasswordStrength } from '../utils/validation.js';
import { logger } from '../utils/logger.js';

/**
 * Register a new user
 * @route POST /api/auth/register
 */
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      await Log.createLog({
        eventType: 'AUTH_REGISTER',
        level: 'warn',
        username,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Registration failed: Missing required fields',
      });

      return res.status(400).json({
        success: false,
        error: 'Please provide username, email, and password',
      });
    }

    // Validate password strength (OWASP guidelines)
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
      await Log.createLog({
        eventType: 'AUTH_REGISTER',
        level: 'warn',
        username,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Registration failed: Weak password',
        details: { errors: passwordValidation.errors },
      });

      return res.status(400).json({
        success: false,
        error: 'Password does not meet security requirements',
        details: passwordValidation.errors,
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      await Log.createLog({
        eventType: 'AUTH_REGISTER',
        level: 'warn',
        username,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Registration failed: User already exists',
      });

      return res.status(409).json({
        success: false,
        error: 'User with this email or username already exists',
      });
    }

    // Create new user (password will be hashed by pre-save hook)
    const user = await User.create({
      username,
      email,
      password,
    });

    // Generate JWT token
    const token = generateToken(user._id);

    // Log successful registration
    await Log.createLog({
      eventType: 'AUTH_REGISTER',
      level: 'info',
      user: user._id,
      username,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      success: true,
      message: `User registered successfully: ${username}`,
    });

    logger.info(`New user registered: ${username}`);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.getPublicProfile(),
        token,
      },
    });
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);

    await Log.createLog({
      eventType: 'AUTH_REGISTER',
      level: 'error',
      username: req.body.username,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      success: false,
      message: 'Registration error',
      error: {
        message: error.message,
        stack: error.stack,
      },
    });

    res.status(500).json({
      success: false,
      error: 'Registration failed. Please try again.',
    });
  }
};

/**
 * Login user
 * @route POST /api/auth/login
 */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      await Log.createLog({
        eventType: 'AUTH_LOGIN_FAILURE',
        level: 'warn',
        username: email,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Login failed: Missing credentials',
      });

      return res.status(400).json({
        success: false,
        error: 'Please provide email and password',
      });
    }

    // Find user (include password for comparison)
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      await Log.createLog({
        eventType: 'AUTH_LOGIN_FAILURE',
        level: 'warn',
        username: email,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Login failed: User not found',
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      await Log.createLog({
        eventType: 'AUTH_LOGIN_FAILURE',
        level: 'warn',
        user: user._id,
        username: user.username,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: false,
        message: 'Login failed: Invalid password',
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
      });
    }

    // Update user online status
    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    // Generate JWT token
    const token = generateToken(user._id);

    // Log successful login
    await Log.createLog({
      eventType: 'AUTH_LOGIN_SUCCESS',
      level: 'info',
      user: user._id,
      username: user.username,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      success: true,
      message: `User logged in: ${user.username}`,
    });

    logger.info(`User logged in: ${user.username}`);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.getPublicProfile(),
        token,
      },
    });
  } catch (error) {
    logger.error(`Login error: ${error.message}`);

    await Log.createLog({
      eventType: 'AUTH_LOGIN_FAILURE',
      level: 'error',
      username: req.body.email,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      success: false,
      message: 'Login error',
      error: {
        message: error.message,
        stack: error.stack,
      },
    });

    res.status(500).json({
      success: false,
      error: 'Login failed. Please try again.',
    });
  }
};

/**
 * Logout user
 * @route POST /api/auth/logout
 */
export const logout = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (user) {
      user.isOnline = false;
      user.lastSeen = new Date();
      user.socketId = null;
      await user.save();

      await Log.createLog({
        eventType: 'AUTH_LOGOUT',
        level: 'info',
        user: user._id,
        username: user.username,
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        success: true,
        message: `User logged out: ${user.username}`,
      });

      logger.info(`User logged out: ${user.username}`);
    }

    res.status(200).json({
      success: true,
      message: 'Logout successful',
    });
  } catch (error) {
    logger.error(`Logout error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Logout failed. Please try again.',
    });
  }
};

/**
 * Get current user profile
 * @route GET /api/auth/me
 */
export const getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error(`Get current user error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to get user data',
    });
  }
};

/**
 * Update user's public key
 * @route PUT /api/auth/public-key
 */
export const updatePublicKey = async (req, res) => {
  try {
    const { publicKey } = req.body;

    if (!publicKey) {
      return res.status(400).json({
        success: false,
        error: 'Public key is required',
      });
    }

    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
      });
    }

    user.publicKey = publicKey;
    await user.save();

    logger.info(`Public key updated for user: ${user.username}`);

    res.status(200).json({
      success: true,
      message: 'Public key updated successfully',
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error(`Update public key error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to update public key',
    });
  }
};

/**
 * Get user by ID (for retrieving public keys)
 * @route GET /api/auth/user/:userId
 */
export const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: user.getPublicProfile(),
      },
    });
  } catch (error) {
    logger.error(`Get user by ID error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to get user data',
    });
  }
};

/**
 * Search users by username
 * @route GET /api/auth/users/search
 */
export const searchUsers = async (req, res) => {
  try {
    const { query } = req.query;

    if (!query || query.length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Search query must be at least 2 characters',
      });
    }

    const users = await User.find({
      username: { $regex: query, $options: 'i' },
    })
      .limit(10)
      .select('username email publicKey isOnline lastSeen createdAt');

    res.status(200).json({
      success: true,
      data: {
        users: users.map((user) => user.getPublicProfile()),
      },
    });
  } catch (error) {
    logger.error(`Search users error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to search users',
    });
  }
};

export default {
  register,
  login,
  logout,
  getCurrentUser,
  updatePublicKey,
  getUserById,
  searchUsers,
};

