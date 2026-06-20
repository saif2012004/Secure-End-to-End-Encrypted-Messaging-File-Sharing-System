import { create } from 'zustand';
import { groupsAPI } from '../services/api';
import { createEncryptedEnvelope, weakDecryptEnvelope } from '../services/encryptionService';
import {
  startKeyExchange,
  getSessionKey,
  waitForSessionKey,
  nextSessionSeq,
  getIdentityPublicB64,
  getPeerIdentity,
  signData,
  verifyData,
} from '../services/keyExchangeService';
import { useAuthStore } from './authStore';
import { base64ToBytes, bytesToBase64 } from '../crypto/messageFormat';
import { unpackPayload } from '../crypto/aesGcm';
import { cachePlaintext, getCachedPlaintext } from '../services/messageCache';

// --- local persistence of OUR OWN sent group messages (plaintext, our device only) ---
const outboxKey = (groupId) => `group_outbox_${groupId}`;
function loadOutbox(groupId) {
  try {
    return JSON.parse(localStorage.getItem(outboxKey(groupId)) || '[]');
  } catch {
    return [];
  }
}
function saveOutboxItem(groupId, item) {
  const list = loadOutbox(groupId);
  list.push(item);
  const capped = list.slice(-200);
  localStorage.setItem(outboxKey(groupId), JSON.stringify(capped));
}

// Build a decryptable envelope from a stored/relayed group message copy
function buildEnvelope(rec, senderId, recipientId) {
  if (rec.envelope) {
    return typeof rec.envelope === 'string' ? JSON.parse(rec.envelope) : rec.envelope;
  }
  if (rec.payload) {
    return {
      v: rec.v || 1,
      sender_id: senderId,
      recipient_id: recipientId,
      nonce: rec.nonce || `grp-${rec._id || rec.messageId || Date.now()}`,
      timestamp: Date.now(),
      seq: rec.seq || 0,
      payload: rec.payload,
    };
  }
  if (rec.ciphertext && rec.iv && rec.tag) {
    const ct = base64ToBytes(rec.ciphertext);
    const iv = base64ToBytes(rec.iv);
    const tag = base64ToBytes(rec.tag);
    const combined = new Uint8Array(ct.byteLength + iv.byteLength + tag.byteLength);
    combined.set(ct, 0);
    combined.set(iv, ct.byteLength);
    combined.set(tag, ct.byteLength + iv.byteLength);
    return {
      v: rec.v || 1,
      sender_id: senderId,
      recipient_id: recipientId,
      nonce: rec.nonce || `grp-${rec._id || rec.messageId || Date.now()}`,
      timestamp: Date.now(),
      seq: rec.seq || 0,
      payload: bytesToBase64(combined),
    };
  }
  return null;
}

export const useGroupStore = create((set, get) => ({
  groups: [],
  selectedGroup: null,
  groupMessages: [],
  isLoadingGroup: false,
  unreadByGroup: {},

  fetchGroups: async () => {
    try {
      const res = await groupsAPI.getMyGroups();
      if (res.success) {
        const groups = res.data.groups.map((g) => ({
          ...g,
          id: g._id,
        }));
        set({ groups });
      }
    } catch (e) {
      console.error('Failed to fetch groups', e);
    }
  },

  createGroup: async (name, memberIds) => {
    const res = await groupsAPI.createGroup(name, memberIds);
    if (res.success) {
      const g = { ...res.data.group, id: res.data.group._id };
      set((s) => ({ groups: [g, ...s.groups.filter((x) => x.id !== g.id)] }));
      return g;
    }
    throw new Error(res.error || 'Failed to create group');
  },

  addGroup: (group) => {
    const g = { ...group, id: group._id || group.id };
    set((s) => (s.groups.some((x) => x.id === g.id) ? {} : { groups: [g, ...s.groups] }));
  },

  // Replace a group in the list (and the selected group) after an update
  updateGroup: (group) => {
    const g = { ...group, id: group._id || group.id };
    set((s) => ({
      groups: s.groups.some((x) => x.id === g.id)
        ? s.groups.map((x) => (x.id === g.id ? g : x))
        : [g, ...s.groups],
      selectedGroup: s.selectedGroup?.id === g.id ? g : s.selectedGroup,
    }));
  },

  // Remove a group locally (we left it or were removed / it was deleted)
  removeGroupFromList: (groupId) => {
    set((s) => ({
      groups: s.groups.filter((x) => x.id !== groupId),
      selectedGroup: s.selectedGroup?.id === groupId ? null : s.selectedGroup,
      groupMessages: s.selectedGroup?.id === groupId ? [] : s.groupMessages,
    }));
  },

  renameGroup: async (groupId, name) => {
    const res = await groupsAPI.renameGroup(groupId, name);
    if (res.success) get().updateGroup(res.data.group);
    else throw new Error(res.error || 'Failed to rename group');
  },

  addMembers: async (groupId, memberIds) => {
    const res = await groupsAPI.addMembers(groupId, memberIds);
    if (res.success) get().updateGroup(res.data.group);
    else throw new Error(res.error || 'Failed to add members');
  },

  removeMember: async (groupId, memberId) => {
    const res = await groupsAPI.removeMember(groupId, memberId);
    if (res.success) get().updateGroup(res.data.group);
    else throw new Error(res.error || 'Failed to remove member');
  },

  leaveGroup: async (groupId) => {
    const res = await groupsAPI.leaveGroup(groupId);
    if (res.success) get().removeGroupFromList(groupId);
    else throw new Error(res.error || 'Failed to leave group');
  },

  selectGroup: async (group) => {
    const authUser = useAuthStore.getState().user;
    set({ selectedGroup: group, groupMessages: [], isLoadingGroup: true });
    get().clearGroupUnread(group.id);

    // Establish session keys with every other member (enables send + receive)
    (group.members || []).forEach((m) => {
      const mid = m._id || m.id;
      if (mid && mid !== authUser?.id) {
        startKeyExchange(mid, m.username).catch(() => {});
      }
    });

    await get().fetchGroupMessages(group.id);
  },

  fetchGroupMessages: async (groupId) => {
    try {
      const authUser = useAuthStore.getState().user;
      const res = await groupsAPI.getGroupMessages(groupId);
      const received = res.success ? res.data.messages : [];

      const decrypted = await Promise.all(
        received.map(async (msg) => {
          const senderId = msg.sender?._id || msg.sender;
          let text = '[🔒 Encrypted Message]';
          let failed = false;
          try {
            const key = await getSessionKey(senderId);
            const env = buildEnvelope(msg, senderId, authUser?.id);
            if (key && env) {
              // Replay protection for group fan-out is enforced server-side
              // (unique sender+recipient+seq); decrypt without the strict
              // client-side seq/nonce check which false-positives across sessions.
              text = await weakDecryptEnvelope(env, key);
            } else {
              failed = true;
            }
          } catch (e) {
            failed = true;
          }
          // Persistent history for groups too
          if (!failed && text && text !== '[🔒 Encrypted Message]') {
            cachePlaintext(msg._id, text);
          } else {
            const cached = await getCachedPlaintext(msg._id);
            if (cached != null) {
              text = cached;
              failed = false;
            }
          }
          // Verify sender signature
          let verified = false;
          if (msg.signature && msg.payload) {
            const senderPub = await getPeerIdentity(senderId);
            if (senderPub) verified = await verifyData(msg.payload, msg.signature, senderPub);
          }
          return {
            id: msg._id,
            senderId,
            senderUsername: msg.sender?.username,
            text,
            timestamp: msg.createdAt || msg.timestamp,
            isEncrypted: true,
            decryptionFailed: failed,
            verified,
          };
        })
      );

      // Merge our own sent messages (kept locally in plaintext)
      const mine = loadOutbox(groupId);
      const all = [...decrypted, ...mine].sort(
        (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
      );

      set({ groupMessages: all, isLoadingGroup: false });
    } catch (e) {
      console.error('Failed to fetch group messages', e);
      set({ isLoadingGroup: false });
    }
  },

  sendGroupMessage: async (plaintext) => {
    const group = get().selectedGroup;
    if (!group) throw new Error('No group selected');
    const authUser = useAuthStore.getState().user;
    const identity = await getIdentityPublicB64();

    const others = (group.members || [])
      .map((m) => ({ id: m._id || m.id, username: m.username }))
      .filter((m) => m.id && m.id !== authUser?.id);

    const copies = [];
    for (const member of others) {
      const key =
        (await getSessionKey(member.id)) ||
        (await waitForSessionKey(member.id, member.username, 6000));
      if (!key) {
        console.warn('No session key for group member, skipping', member.username);
        continue;
      }
      const seq = await nextSessionSeq(member.id);
      const env = await createEncryptedEnvelope(plaintext, key, member.id, identity, seq);
      const packed = base64ToBytes(env.payload);
      const split = unpackPayload(packed);
      const signature = await signData(env.payload); // sign each per-recipient copy
      copies.push({
        recipientId: member.id,
        ciphertext: bytesToBase64(split.ciphertext),
        iv: bytesToBase64(split.iv),
        tag: bytesToBase64(split.tag),
        seq: env.seq,
        nonce: env.nonce,
        payload: env.payload,
        timestamp: env.timestamp,
        v: env.v, // carry the crypto version (v2 = per-message ratchet key)
        signature,
      });
    }

    if (copies.length === 0) {
      throw new Error('Could not establish keys with any group member yet. Try again in a moment.');
    }

    await groupsAPI.sendGroupMessage(group.id, copies);

    // Optimistically show + persist our own message locally
    const mineMsg = {
      id: `grp_${Date.now()}`,
      senderId: authUser?.id,
      senderUsername: authUser?.username,
      text: plaintext,
      timestamp: Date.now(),
      isEncrypted: true,
      mine: true,
      verified: true,
    };
    saveOutboxItem(group.id, mineMsg);
    set((s) => ({ groupMessages: [...s.groupMessages, mineMsg] }));
    // bump ordering
    set((s) => ({
      groups: [...s.groups].sort((a, b) =>
        a.id === group.id ? -1 : b.id === group.id ? 1 : 0
      ),
    }));
  },

  receiveGroupMessage: async (data) => {
    const authUser = useAuthStore.getState().user;
    const senderId = data.senderId;
    if (senderId === authUser?.id) return; // ignore our own fan-out echoes

    let text = '[🔒 Encrypted Message]';
    try {
      const key =
        (await getSessionKey(senderId)) ||
        (await waitForSessionKey(senderId, data.senderUsername, 6000));
      const env = buildEnvelope(data, senderId, authUser?.id);
      if (key && env) {
        text = await weakDecryptEnvelope(env, key);
        if (data.messageId && text) cachePlaintext(data.messageId, text);
      }
    } catch (e) {
      console.error('Group message decrypt failed', e);
    }

    let verified = false;
    if (data.signature && data.payload) {
      const senderPub = await getPeerIdentity(senderId);
      if (senderPub) verified = await verifyData(data.payload, data.signature, senderPub);
    }

    const message = {
      id: data.messageId || `grp_${Date.now()}`,
      senderId,
      senderUsername: data.senderUsername,
      text,
      timestamp: data.timestamp || Date.now(),
      isEncrypted: true,
      verified,
    };

    const { selectedGroup } = get();
    if (selectedGroup && selectedGroup.id === data.groupId) {
      set((s) => ({ groupMessages: [...s.groupMessages, message] }));
    } else {
      set((s) => ({
        unreadByGroup: {
          ...s.unreadByGroup,
          [data.groupId]: (s.unreadByGroup[data.groupId] || 0) + 1,
        },
      }));
    }
  },

  clearGroupUnread: (groupId) => {
    set((s) => ({ unreadByGroup: { ...s.unreadByGroup, [groupId]: 0 } }));
  },

  clearSelectedGroup: () => set({ selectedGroup: null, groupMessages: [] }),
}));
