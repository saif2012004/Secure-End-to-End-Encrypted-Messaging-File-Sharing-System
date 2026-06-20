import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { usersAPI } from '../services/api';
import { useAuthStore } from '../store/authStore';
import { useGroupStore } from '../store/groupStore';
import { backdropVariant, modalVariant } from '../animations/variants';
import '../styles/GroupManageModal.css';

function GroupManageModal({ onClose }) {
  const { user } = useAuthStore();
  const group = useGroupStore((s) => s.selectedGroup);
  const { renameGroup, addMembers, removeMember, leaveGroup } = useGroupStore();

  const [name, setName] = useState(group?.name || '');
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  if (!group) return null;

  const isOwner = String(group.owner?._id || group.owner) === user?.id;
  const memberIds = new Set((group.members || []).map((m) => String(m._id || m.id)));

  const run = async (fn) => {
    setBusy(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError(e.message || 'Action failed');
    } finally {
      setBusy(false);
    }
  };

  const doRename = () => {
    if (!name.trim() || name.trim() === group.name) return;
    run(() => renameGroup(group.id, name.trim()));
  };

  const doSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    try {
      const r = await usersAPI.searchUsers(query.trim());
      if (r.success) {
        setResults(r.data.users.filter((u) => u.id !== user?.id && !memberIds.has(u.id)));
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSearching(false);
    }
  };

  const doAdd = (u) =>
    run(async () => {
      await addMembers(group.id, [u.id]);
      setResults((prev) => prev.filter((x) => x.id !== u.id));
    });

  const doRemove = (m) => run(() => removeMember(group.id, m._id || m.id));

  const doLeave = () =>
    run(async () => {
      await leaveGroup(group.id);
      onClose();
    });

  return (
    <motion.div
      className="gm-overlay"
      onClick={onClose}
      variants={backdropVariant}
      initial="hidden"
      animate="show"
      exit="exit"
    >
      <motion.div
        className="gm-modal"
        onClick={(e) => e.stopPropagation()}
        variants={modalVariant}
        initial="hidden"
        animate="show"
        exit="exit"
      >
        <div className="gm-header">
          <h3>⚙️ Manage “{group.name}”</h3>
          <button className="gm-close" onClick={onClose}>✕</button>
        </div>

        <div className="gm-body">
          {/* Rename (owner only) */}
          {isOwner && (
            <div className="gm-section">
              <label className="gm-label">Group name</label>
              <div className="gm-rename">
                <input
                  className="gm-input"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={60}
                />
                <button
                  className="gm-btn-primary"
                  onClick={doRename}
                  disabled={busy || !name.trim() || name.trim() === group.name}
                >
                  Save
                </button>
              </div>
            </div>
          )}

          {/* Members */}
          <div className="gm-section">
            <label className="gm-label">{group.members?.length || 0} members</label>
            <div className="gm-members">
              {(group.members || []).map((m) => {
                const mid = m._id || m.id;
                const owner = String(mid) === String(group.owner?._id || group.owner);
                const me = String(mid) === user?.id;
                return (
                  <div key={mid} className="gm-member">
                    <div className="gm-avatar">{(m.username || '?').charAt(0).toUpperCase()}</div>
                    <div className="gm-member-info">
                      <span className="gm-name">
                        {m.username}{me ? ' (you)' : ''}
                      </span>
                      <span className="gm-email">{m.email}</span>
                    </div>
                    {owner ? (
                      <span className="gm-owner-tag">Owner</span>
                    ) : isOwner ? (
                      <button className="gm-remove" title="Remove" onClick={() => doRemove(m)} disabled={busy}>
                        ✕
                      </button>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Add members (owner only) */}
          {isOwner && (
            <div className="gm-section">
              <label className="gm-label">Add members</label>
              <form className="gm-search" onSubmit={doSearch}>
                <input
                  className="gm-input"
                  placeholder="Search users…"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
                <button type="submit" className="gm-search-btn" disabled={searching}>
                  {searching ? '⏳' : '🔍'}
                </button>
              </form>
              <AnimatePresence>
                {results.map((u) => (
                  <motion.div
                    key={u.id}
                    className="gm-result"
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 10 }}
                    onClick={() => doAdd(u)}
                  >
                    <div className="gm-avatar small">{u.username.charAt(0).toUpperCase()}</div>
                    <span className="gm-name">{u.username}</span>
                    <span className="gm-add">＋</span>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          )}

          {error && <div className="gm-error">{error}</div>}
        </div>

        <div className="gm-footer">
          <button className="gm-leave" onClick={doLeave} disabled={busy}>
            🚪 Leave group
          </button>
          <button className="gm-btn-secondary" onClick={onClose}>Close</button>
        </div>
      </motion.div>
    </motion.div>
  );
}

export default GroupManageModal;
