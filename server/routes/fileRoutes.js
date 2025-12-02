import express from 'express';
import {
  uploadFileChunk,
  downloadFile,
  getFileProgress,
  deleteFileChunks,
} from '../controllers/fileController.js';
import { protect } from '../middlewares/authMiddleware.js';
import {
  validateFileChunk,
  validateObjectId,
} from '../middlewares/validationMiddleware.js';

const router = express.Router();

// All file routes are protected
router.use(protect);

// File operations
router.post('/upload-chunk', validateFileChunk, uploadFileChunk);
router.get('/download/:messageId', validateObjectId, downloadFile);
router.get('/progress/:messageId', validateObjectId, getFileProgress);
router.delete('/:messageId', validateObjectId, deleteFileChunks);

export default router;

