import mongoose from 'mongoose';

/**
 * FileChunk Model
 * Stores encrypted file chunks with metadata
 * Large files are split into chunks for efficient transmission
 * Each chunk is encrypted client-side before upload
 */
const fileChunkSchema = new mongoose.Schema(
  {
    message: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Message',
      required: [true, 'Message reference is required'],
      index: true,
    },
    chunkNumber: {
      type: Number,
      required: [true, 'Chunk number is required'],
      min: 0,
    },
    totalChunks: {
      type: Number,
      required: [true, 'Total chunks is required'],
      min: 1,
    },
    // Encrypted chunk data (as Base64 string)
    encryptedData: {
      type: String,
      required: [true, 'Encrypted data is required'],
    },
    // Chunk-specific IV
    iv: {
      type: String,
      required: [true, 'IV is required'],
    },
    // Chunk-specific authentication tag
    tag: {
      type: String,
      required: [true, 'Authentication tag is required'],
    },
    // Chunk size (for verification)
    size: {
      type: Number,
      required: [true, 'Chunk size is required'],
    },
    // Hash of encrypted chunk (for integrity verification)
    hash: {
      type: String,
      required: [true, 'Chunk hash is required'],
    },
  },
  {
    timestamps: true,
  }
);

// Compound index for efficient chunk retrieval
fileChunkSchema.index({ message: 1, chunkNumber: 1 }, { unique: true });

// Static method to get all chunks for a message
fileChunkSchema.statics.getMessageChunks = async function (messageId) {
  return this.find({ message: messageId }).sort({ chunkNumber: 1 });
};

// Static method to verify all chunks are present
fileChunkSchema.statics.verifyChunksComplete = async function (messageId, expectedTotal) {
  const count = await this.countDocuments({ message: messageId });
  return count === expectedTotal;
};

const FileChunk = mongoose.model('FileChunk', fileChunkSchema);

export default FileChunk;

