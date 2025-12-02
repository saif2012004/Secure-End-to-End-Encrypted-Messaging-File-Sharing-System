import FileChunk from '../models/FileChunk.js';
import Message from '../models/Message.js';
import Log from '../models/Log.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';

/**
 * Upload encrypted file chunk
 * @route POST /api/files/upload-chunk
 */
export const uploadFileChunk = async (req, res) => {
  try {
    const {
      messageId,
      chunkNumber,
      totalChunks,
      encryptedData,
      iv,
      tag,
      size,
      hash,
    } = req.body;

    // Validate required fields
    if (
      !messageId ||
      chunkNumber === undefined ||
      !totalChunks ||
      !encryptedData ||
      !iv ||
      !tag ||
      !size ||
      !hash
    ) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
      });
    }

    // Validate message ID
    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    // Verify message exists and user is the sender
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    // Check if chunk already exists (prevent duplicates)
    const existingChunk = await FileChunk.findOne({
      message: messageId,
      chunkNumber,
    });

    if (existingChunk) {
      return res.status(409).json({
        success: false,
        error: 'Chunk already uploaded',
      });
    }

    // Create file chunk
    const fileChunk = await FileChunk.create({
      message: messageId,
      chunkNumber,
      totalChunks,
      encryptedData,
      iv,
      tag,
      size,
      hash,
    });

    // Check if all chunks are uploaded
    const uploadedChunks = await FileChunk.countDocuments({ message: messageId });
    const isComplete = uploadedChunks === totalChunks;

    // If all chunks uploaded, update message with file chunk references
    if (isComplete) {
      const allChunks = await FileChunk.find({ message: messageId }).sort({ chunkNumber: 1 });
      
      message.fileMetadata.fileChunks = allChunks.map(chunk => chunk._id);
      await message.save();

      await Log.createLog({
        eventType: 'FILE_UPLOAD',
        level: 'info',
        user: req.user.id,
        ipAddress: req.ip,
        success: true,
        message: `File upload completed for message ${messageId}`,
        details: {
          messageId,
          totalChunks,
          totalSize: allChunks.reduce((sum, chunk) => sum + chunk.size, 0),
        },
      });

      logger.info(`File upload completed for message: ${messageId}`);
    }

    res.status(201).json({
      success: true,
      message: 'File chunk uploaded successfully',
      data: {
        chunkId: fileChunk._id,
        chunkNumber: fileChunk.chunkNumber,
        totalChunks: fileChunk.totalChunks,
        isComplete,
      },
    });
  } catch (error) {
    logger.error(`Upload file chunk error: ${error.message}`);

    await Log.createLog({
      eventType: 'FILE_UPLOAD',
      level: 'error',
      user: req.user.id,
      ipAddress: req.ip,
      success: false,
      message: 'File chunk upload failed',
      error: {
        message: error.message,
      },
    });

    res.status(500).json({
      success: false,
      error: 'Failed to upload file chunk',
    });
  }
};

/**
 * Download file chunks for a message
 * @route GET /api/files/download/:messageId
 */
export const downloadFile = async (req, res) => {
  try {
    const { messageId } = req.params;

    // Validate message ID
    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    // Verify message exists
    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    // Verify user is sender or recipient
    if (
      message.sender.toString() !== req.user.id &&
      message.recipient.toString() !== req.user.id
    ) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    // Get all file chunks
    const chunks = await FileChunk.getMessageChunks(messageId);

    if (!chunks || chunks.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No file chunks found',
      });
    }

    // Verify all chunks are present
    const totalChunks = chunks[0].totalChunks;
    const isComplete = await FileChunk.verifyChunksComplete(messageId, totalChunks);

    if (!isComplete) {
      return res.status(400).json({
        success: false,
        error: 'File upload incomplete',
        details: {
          expected: totalChunks,
          received: chunks.length,
        },
      });
    }

    await Log.createLog({
      eventType: 'FILE_DOWNLOAD',
      level: 'info',
      user: req.user.id,
      ipAddress: req.ip,
      success: true,
      message: `File downloaded for message ${messageId}`,
      details: {
        messageId,
        totalChunks,
      },
    });

    res.status(200).json({
      success: true,
      data: {
        messageId,
        fileMetadata: message.fileMetadata,
        chunks: chunks.map((chunk) => ({
          chunkNumber: chunk.chunkNumber,
          encryptedData: chunk.encryptedData,
          iv: chunk.iv,
          tag: chunk.tag,
          size: chunk.size,
          hash: chunk.hash,
        })),
      },
    });
  } catch (error) {
    logger.error(`Download file error: ${error.message}`);

    await Log.createLog({
      eventType: 'FILE_DOWNLOAD',
      level: 'error',
      user: req.user.id,
      ipAddress: req.ip,
      success: false,
      message: 'File download failed',
      error: {
        message: error.message,
      },
    });

    res.status(500).json({
      success: false,
      error: 'Failed to download file',
    });
  }
};

/**
 * Get file upload progress
 * @route GET /api/files/progress/:messageId
 */
export const getFileProgress = async (req, res) => {
  try {
    const { messageId } = req.params;

    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    // Verify user is sender or recipient
    if (
      message.sender.toString() !== req.user.id &&
      message.recipient.toString() !== req.user.id
    ) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    // Get uploaded chunks
    const chunks = await FileChunk.find({ message: messageId }).sort({ chunkNumber: 1 });
    
    const totalChunks = message.fileMetadata?.fileChunks?.length || 
                        (chunks.length > 0 ? chunks[0].totalChunks : 0);
    const uploadedChunks = chunks.length;

    res.status(200).json({
      success: true,
      data: {
        messageId,
        totalChunks,
        uploadedChunks,
        isComplete: uploadedChunks === totalChunks && totalChunks > 0,
        percentage: totalChunks > 0 ? Math.round((uploadedChunks / totalChunks) * 100) : 0,
      },
    });
  } catch (error) {
    logger.error(`Get file progress error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to get file progress',
    });
  }
};

/**
 * Delete file chunks (when message is deleted)
 * @route DELETE /api/files/:messageId
 */
export const deleteFileChunks = async (req, res) => {
  try {
    const { messageId } = req.params;

    if (!isValidObjectId(messageId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid message ID',
      });
    }

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({
        success: false,
        error: 'Message not found',
      });
    }

    // Only sender can delete file chunks
    if (message.sender.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        error: 'Unauthorized',
      });
    }

    // Delete all chunks
    const result = await FileChunk.deleteMany({ message: messageId });

    logger.info(`Deleted ${result.deletedCount} file chunks for message: ${messageId}`);

    res.status(200).json({
      success: true,
      message: 'File chunks deleted successfully',
      data: {
        deletedCount: result.deletedCount,
      },
    });
  } catch (error) {
    logger.error(`Delete file chunks error: ${error.message}`);

    res.status(500).json({
      success: false,
      error: 'Failed to delete file chunks',
    });
  }
};

export default {
  uploadFileChunk,
  downloadFile,
  getFileProgress,
  deleteFileChunks,
};

