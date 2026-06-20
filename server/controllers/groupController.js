import Group from '../models/Group.js';
import Message from '../models/Message.js';
import User from '../models/User.js';
import Log from '../models/Log.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';

const PALETTE = ['#8b5cf6', '#6366f1', '#22d3ee', '#10b981', '#f59e0b', '#f43f5e', '#ec4899'];

/**
 * Create a new group
 * @route POST /api/groups
 */
export const createGroup = async (req, res) => {
  try {
    const { name, memberIds } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: 'Group name is required' });
    }
    if (!Array.isArray(memberIds) || memberIds.length < 1) {
      return res.status(400).json({ success: false, error: 'Select at least one member' });
    }
    if (memberIds.some((id) => !isValidObjectId(id))) {
      return res.status(400).json({ success: false, error: 'Invalid member id' });
    }

    // Validate members exist; always include the owner
    const uniqueMembers = Array.from(new Set([...memberIds.map(String), req.user.id]));
    const found = await User.find({ _id: { $in: uniqueMembers } }).select('_id');
    if (found.length !== uniqueMembers.length) {
      return res.status(400).json({ success: false, error: 'One or more members not found' });
    }

    const group = await Group.create({
      name: name.trim(),
      owner: req.user.id,
      members: uniqueMembers,
      avatarColor: PALETTE[Math.floor(Math.random() * PALETTE.length)],
    });

    await group.populate('members', 'username email isOnline lastSeen');

    await Log.createLog({
      eventType: 'MESSAGE_SENT',
      level: 'info',
      user: req.user.id,
      success: true,
      message: `Group created: ${group.name}`,
      details: { groupId: group._id, memberCount: uniqueMembers.length },
    });

    // Notify members in real time so the group appears in their sidebar
    const io = req.app.get('io');
    if (io) {
      uniqueMembers.forEach((memberId) => {
        if (memberId !== req.user.id) io.to(memberId).emit('group:created', { group });
      });
    }

    res.status(201).json({ success: true, data: { group } });
  } catch (error) {
    logger.error(`Create group error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to create group' });
  }
};

/**
 * List groups the current user belongs to
 * @route GET /api/groups
 */
export const getMyGroups = async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.id })
      .sort({ updatedAt: -1 })
      .populate('members', 'username email isOnline lastSeen');

    res.status(200).json({ success: true, data: { groups } });
  } catch (error) {
    logger.error(`Get groups error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to fetch groups' });
  }
};

/**
 * Get messages for a group (only the copies encrypted for the current user)
 * @route GET /api/groups/:groupId/messages
 */
export const getGroupMessages = async (req, res) => {
  try {
    const { groupId } = req.params;
    const { limit = 50, skip = 0 } = req.query;

    if (!isValidObjectId(groupId)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.members.map(String).includes(req.user.id)) {
      return res.status(403).json({ success: false, error: 'Not a member of this group' });
    }

    // A member can only read the fan-out copies addressed to them
    const messages = await Message.find({ group: groupId, recipient: req.user.id })
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .populate('sender', 'username email');

    res.status(200).json({
      success: true,
      data: { messages: messages.reverse(), count: messages.length },
    });
  } catch (error) {
    logger.error(`Get group messages error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to fetch group messages' });
  }
};

/**
 * Send a group message (client provides one encrypted copy per recipient member)
 * @route POST /api/groups/:groupId/messages
 */
export const sendGroupMessage = async (req, res) => {
  try {
    const { groupId } = req.params;
    const { copies, messageType } = req.body;

    if (!isValidObjectId(groupId)) {
      return res.status(400).json({ success: false, error: 'Invalid group id' });
    }
    if (!Array.isArray(copies) || copies.length === 0) {
      return res.status(400).json({ success: false, error: 'No encrypted copies provided' });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });

    const memberIds = group.members.map(String);
    if (!memberIds.includes(req.user.id)) {
      return res.status(403).json({ success: false, error: 'Not a member of this group' });
    }

    const io = req.app.get('io');
    const sender = await User.findById(req.user.id).select('username');
    const stored = [];

    for (const copy of copies) {
      const { recipientId, ciphertext, iv, tag, seq, nonce, payload, timestamp, v, signature } = copy;
      // Only allow sending to actual members
      if (!recipientId || !memberIds.includes(String(recipientId))) continue;
      if (!ciphertext || !iv || !tag || seq === undefined) continue;

      const msg = await Message.create({
        sender: req.user.id,
        recipient: recipientId,
        group: groupId,
        ciphertext,
        iv,
        tag,
        seq,
        nonce: nonce || null,
        payload: payload || null,
        timestamp: timestamp || Date.now(),
        v: v || 1,
        signature: signature || null,
        messageType: messageType || 'text',
      });
      stored.push(msg._id);

      // Relay in real time to that member (skip the sender's own copy)
      if (io && String(recipientId) !== req.user.id) {
        io.to(String(recipientId)).emit('group_message', {
          groupId,
          senderId: req.user.id,
          senderUsername: sender?.username,
          messageId: msg._id,
          ciphertext,
          iv,
          tag,
          seq,
          nonce,
          payload,
          v: v || 1,
          signature: signature || null,
          timestamp: msg.timestamp,
          messageType: messageType || 'text',
        });
      }
    }

    // Bump group's updatedAt so it sorts to the top
    group.updatedAt = new Date();
    await group.save();

    res.status(201).json({ success: true, data: { count: stored.length } });
  } catch (error) {
    logger.error(`Send group message error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to send group message' });
  }
};

/**
 * Rename a group (owner only)
 * @route PATCH /api/groups/:groupId
 */
export const renameGroup = async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name } = req.body;
    if (!isValidObjectId(groupId)) return res.status(400).json({ success: false, error: 'Invalid group id' });
    if (!name || !name.trim()) return res.status(400).json({ success: false, error: 'Group name is required' });

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (String(group.owner) !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Only the group owner can rename it' });
    }

    group.name = name.trim();
    await group.save();
    await group.populate('members', 'username email isOnline lastSeen');

    notifyGroupUpdated(req, group);
    res.status(200).json({ success: true, data: { group } });
  } catch (error) {
    logger.error(`Rename group error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to rename group' });
  }
};

/**
 * Add members to a group (owner only)
 * @route POST /api/groups/:groupId/members
 */
export const addMembers = async (req, res) => {
  try {
    const { groupId } = req.params;
    const { memberIds } = req.body;
    if (!isValidObjectId(groupId)) return res.status(400).json({ success: false, error: 'Invalid group id' });
    if (!Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ success: false, error: 'No members provided' });
    }
    if (memberIds.some((id) => !isValidObjectId(id))) {
      return res.status(400).json({ success: false, error: 'Invalid member id' });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (String(group.owner) !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Only the group owner can add members' });
    }

    const found = await User.find({ _id: { $in: memberIds } }).select('_id');
    if (found.length !== new Set(memberIds.map(String)).size) {
      return res.status(400).json({ success: false, error: 'One or more users not found' });
    }

    const current = new Set(group.members.map(String));
    const added = [];
    memberIds.forEach((id) => {
      if (!current.has(String(id))) {
        group.members.push(id);
        added.push(String(id));
      }
    });
    await group.save();
    await group.populate('members', 'username email isOnline lastSeen');

    const io = req.app.get('io');
    if (io) {
      // New members get the group; existing members get an update
      added.forEach((id) => io.to(id).emit('group:created', { group }));
      group.members.forEach((m) => {
        const mid = String(m._id);
        if (!added.includes(mid)) io.to(mid).emit('group:updated', { group });
      });
    }

    res.status(200).json({ success: true, data: { group } });
  } catch (error) {
    logger.error(`Add members error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to add members' });
  }
};

/**
 * Remove a member from a group (owner only)
 * @route DELETE /api/groups/:groupId/members/:memberId
 */
export const removeMember = async (req, res) => {
  try {
    const { groupId, memberId } = req.params;
    if (!isValidObjectId(groupId) || !isValidObjectId(memberId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (String(group.owner) !== req.user.id) {
      return res.status(403).json({ success: false, error: 'Only the group owner can remove members' });
    }
    if (String(memberId) === String(group.owner)) {
      return res.status(400).json({ success: false, error: 'Owner cannot be removed (use leave / delete)' });
    }

    group.members = group.members.filter((m) => String(m) !== String(memberId));
    await group.save();
    await group.populate('members', 'username email isOnline lastSeen');

    const io = req.app.get('io');
    if (io) {
      io.to(String(memberId)).emit('group:removed', { groupId });
      group.members.forEach((m) => io.to(String(m._id)).emit('group:updated', { group }));
    }

    res.status(200).json({ success: true, data: { group } });
  } catch (error) {
    logger.error(`Remove member error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to remove member' });
  }
};

/**
 * Leave a group (any member). If the owner leaves, ownership transfers; if the
 * group becomes empty it is deleted.
 * @route POST /api/groups/:groupId/leave
 */
export const leaveGroup = async (req, res) => {
  try {
    const { groupId } = req.params;
    if (!isValidObjectId(groupId)) return res.status(400).json({ success: false, error: 'Invalid group id' });

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ success: false, error: 'Group not found' });
    if (!group.members.map(String).includes(req.user.id)) {
      return res.status(403).json({ success: false, error: 'Not a member of this group' });
    }

    group.members = group.members.filter((m) => String(m) !== req.user.id);
    const io = req.app.get('io');

    if (group.members.length === 0) {
      await group.deleteOne();
      if (io) io.to(req.user.id).emit('group:removed', { groupId });
      return res.status(200).json({ success: true, data: { left: true, deleted: true } });
    }

    // Transfer ownership if the owner left
    if (String(group.owner) === req.user.id) {
      group.owner = group.members[0];
    }
    await group.save();
    await group.populate('members', 'username email isOnline lastSeen');

    if (io) {
      io.to(req.user.id).emit('group:removed', { groupId });
      group.members.forEach((m) => io.to(String(m._id)).emit('group:updated', { group }));
    }

    res.status(200).json({ success: true, data: { left: true } });
  } catch (error) {
    logger.error(`Leave group error: ${error.message}`);
    res.status(500).json({ success: false, error: 'Failed to leave group' });
  }
};

// Helper: notify all members that a group changed
function notifyGroupUpdated(req, group) {
  const io = req.app.get('io');
  if (!io) return;
  group.members.forEach((m) => io.to(String(m._id || m)).emit('group:updated', { group }));
}

export default {
  createGroup,
  getMyGroups,
  getGroupMessages,
  sendGroupMessage,
  renameGroup,
  addMembers,
  removeMember,
  leaveGroup,
};
