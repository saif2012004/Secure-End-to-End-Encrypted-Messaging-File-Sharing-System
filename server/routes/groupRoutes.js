import express from 'express';
import {
  createGroup,
  getMyGroups,
  getGroupMessages,
  sendGroupMessage,
  renameGroup,
  addMembers,
  removeMember,
  leaveGroup,
} from '../controllers/groupController.js';
import { protect } from '../middlewares/authMiddleware.js';

const router = express.Router();

// All group routes are protected
router.use(protect);

router.post('/', createGroup);
router.get('/', getMyGroups);
router.get('/:groupId/messages', getGroupMessages);
router.post('/:groupId/messages', sendGroupMessage);

// Management
router.patch('/:groupId', renameGroup);
router.post('/:groupId/members', addMembers);
router.delete('/:groupId/members/:memberId', removeMember);
router.post('/:groupId/leave', leaveGroup);

export default router;
