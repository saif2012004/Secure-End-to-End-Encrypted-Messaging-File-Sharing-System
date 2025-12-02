import mongoose from 'mongoose';

/**
 * Message Model
 * Stores ONLY metadata and encrypted content
 * NO plaintext is stored in the database
 * 
 * Client-side encryption is handled by Members 1 & 2
 * This backend (Member 3) only relays encrypted data
 */
const messageSchema = new mongoose.Schema(
  {
    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Sender is required'],
      index: true,
    },
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Recipient is required'],
      index: true,
    },
    // Encrypted message content (as Base64 string)
    ciphertext: {
      type: String,
      required: [true, 'Ciphertext is required'],
    },
    // Initialization Vector for encryption (as Base64 string)
    iv: {
      type: String,
      required: [true, 'IV is required'],
    },
    // Authentication tag for AEAD schemes (as Base64 string)
    tag: {
      type: String,
      required: [true, 'Authentication tag is required'],
    },
    // Sequence number for replay attack prevention
    seq: {
      type: Number,
      required: [true, 'Sequence number is required'],
      index: true,
    },
    // Digital signature (for message authentication)
    signature: {
      type: String,
      default: null,
    },
    // Message type (text, file, system)
    messageType: {
      type: String,
      enum: ['text', 'file', 'system'],
      default: 'text',
    },
    // File metadata (if messageType is 'file')
    fileMetadata: {
      fileName: String,
      fileSize: Number,
      mimeType: String,
      fileChunks: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'FileChunk',
      }],
    },
    // Delivery status
    delivered: {
      type: Boolean,
      default: false,
    },
    deliveredAt: {
      type: Date,
      default: null,
    },
    // Read status
    read: {
      type: Boolean,
      default: false,
    },
    readAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt
  }
);

// Compound index for efficient querying
messageSchema.index({ sender: 1, recipient: 1, createdAt: -1 });
messageSchema.index({ recipient: 1, delivered: 1 });

// Method to get message metadata without sensitive data
messageSchema.methods.getMetadata = function () {
  return {
    id: this._id,
    sender: this.sender,
    recipient: this.recipient,
    seq: this.seq,
    messageType: this.messageType,
    delivered: this.delivered,
    read: this.read,
    createdAt: this.createdAt,
  };
};

const Message = mongoose.model('Message', messageSchema);

export default Message;

