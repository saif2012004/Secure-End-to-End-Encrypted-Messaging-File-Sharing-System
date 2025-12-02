import mongoose from 'mongoose';

/**
 * Log Model
 * Stores security-relevant events for audit trail
 * Following OWASP Logging recommendations
 */
const logSchema = new mongoose.Schema(
  {
    // Log type/category (OWASP-compliant event types)
    eventType: {
      type: String,
      required: [true, 'Event type is required'],
      enum: [
        // Authentication Events
        'AUTH_LOGIN_SUCCESS',
        'AUTH_LOGIN_FAILURE',
        'AUTH_LOGOUT',
        'AUTH_REGISTER',
        'AUTH_TOKEN_REFRESH',
        'AUTH_PASSWORD_CHANGE',
        'AUTH_INVALID_TOKEN',
        'AUTH_TOKEN_EXPIRED',
        
        // Authorization Events
        'UNAUTHORIZED_ACCESS',
        'FORBIDDEN_ACCESS',
        'PERMISSION_DENIED',
        
        // Message Events
        'MESSAGE_SENT',
        'MESSAGE_RECEIVED',
        'MESSAGE_DELIVERED',
        'MESSAGE_READ',
        'MESSAGE_DELETED',
        
        // File Events
        'FILE_UPLOAD',
        'FILE_UPLOAD_CHUNK',
        'FILE_DOWNLOAD',
        'FILE_DELETED',
        
        // Cryptographic Events
        'KEY_EXCHANGE_RELAY',
        'KEY_EXCHANGE_FAILED',
        'INVALID_SIGNATURE',
        'SIGNATURE_VERIFIED',
        
        // Security Events
        'REPLAY_DETECTED',
        'REPLAY_BLOCKED',
        'SUSPICIOUS_ACTIVITY',
        'ABNORMAL_REQUEST',
        'METADATA_ACCESS',
        
        // Rate Limiting
        'RATE_LIMIT_EXCEEDED',
        'RATE_LIMIT_WARNING',
        
        // Socket Events
        'SOCKET_CONNECT',
        'SOCKET_DISCONNECT',
        'SOCKET_ERROR',
        
        // System Events
        'ERROR',
        'SYSTEM_ERROR',
        'DATABASE_ERROR',
        'VALIDATION_ERROR',
      ],
      index: true,
    },
    // Severity level
    level: {
      type: String,
      enum: ['info', 'warn', 'error', 'critical'],
      default: 'info',
      index: true,
    },
    // User involved (if applicable)
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
      index: true,
    },
    // Username (for failed auth attempts where user may not exist)
    username: {
      type: String,
      default: null,
    },
    // IP address of the client (OWASP: Log source IP)
    ipAddress: {
      type: String,
      default: null,
      index: true, // For security analysis
    },
    // User agent (OWASP: Log client info)
    userAgent: {
      type: String,
      default: null,
    },
    // User from (for relational events like message sending)
    userFrom: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
      index: true,
    },
    // User to (for relational events like message receiving)
    userTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
      index: true,
    },
    // HTTP method (for API requests)
    method: {
      type: String,
      default: null,
    },
    // Request path (for API requests)
    path: {
      type: String,
      default: null,
    },
    // Request metadata (headers, query params, etc.)
    requestMetadata: {
      headers: mongoose.Schema.Types.Mixed,
      query: mongoose.Schema.Types.Mixed,
      params: mongoose.Schema.Types.Mixed,
    },
    // Event details (flexible object for additional data)
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    // Message or description
    message: {
      type: String,
      default: '',
    },
    // Session/Socket ID (if applicable)
    sessionId: {
      type: String,
      default: null,
    },
    // Success or failure flag
    success: {
      type: Boolean,
      default: true,
    },
    // Error details (if applicable)
    error: {
      message: String,
      stack: String,
      code: String,
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt
  }
);

// Indexes for efficient querying
logSchema.index({ createdAt: -1 }); // Most recent logs first
logSchema.index({ eventType: 1, createdAt: -1 });
logSchema.index({ user: 1, createdAt: -1 });
logSchema.index({ level: 1, createdAt: -1 });

// Static method to create a log entry
logSchema.statics.createLog = async function (logData) {
  try {
    const log = new this(logData);
    await log.save();
    return log;
  } catch (error) {
    // Don't throw - we don't want logging failures to break the app
    console.error('Failed to create log entry:', error.message);
    return null;
  }
};

// Static method to get logs by type
logSchema.statics.getLogsByType = async function (eventType, limit = 100) {
  return this.find({ eventType })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('user', 'username email');
};

// Static method to get logs by user
logSchema.statics.getLogsByUser = async function (userId, limit = 100) {
  return this.find({ user: userId })
    .sort({ createdAt: -1 })
    .limit(limit);
};

// Static method to get security alerts (warnings, errors, critical)
logSchema.statics.getSecurityAlerts = async function (limit = 100) {
  return this.find({
    level: { $in: ['warn', 'error', 'critical'] },
  })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('user', 'username email');
};

const Log = mongoose.model('Log', logSchema);

export default Log;

