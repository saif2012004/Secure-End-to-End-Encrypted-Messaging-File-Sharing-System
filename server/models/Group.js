import mongoose from 'mongoose';

/**
 * Group Model
 * Represents a group conversation. The server stores ONLY metadata
 * (name, members, owner) — never any plaintext. Group messages are
 * end-to-end encrypted client-side using pairwise session keys
 * (fan-out), so the server remains zero-knowledge.
 */
const groupSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Group name is required'],
      trim: true,
      maxlength: [60, 'Group name too long'],
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    members: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        index: true,
      },
    ],
    avatarColor: {
      type: String,
      default: '#8b5cf6',
    },
  },
  { timestamps: true }
);

groupSchema.index({ members: 1, updatedAt: -1 });

const Group = mongoose.model('Group', groupSchema);

export default Group;
