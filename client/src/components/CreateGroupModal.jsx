import { useState } from 'react';
import { motion } from 'framer-motion';
import { usersAPI } from '../services/api';
import { useAuthStore } from '../store/authStore';
import { useGroupStore } from '../store/groupStore';
import { backdropVariant, modalVariant } from '../animations/variants';
import '../styles/CreateGroupModal.css';

function CreateGroupModal({ onClose, onCreated }) {
  const [name, setName] = useState('');
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [selected, setSelected] = useState([]);
  const [searching, setSearching] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const { user } = useAuthStore();
  const { createGroup } = useGroupStore();

  const search = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    try {
      const res = await usersAPI.searchUsers(query.trim());
      if (res.success) {
        setResults(res.data.users.filter((u) => u.id !== user?.id));
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSearching(false);
    }
  };

  const toggle = (u) => {
    setSelected((prev) =>
      prev.some((m) => m.id === u.id) ? prev.filter((m) => m.id !== u.id) : [...prev, u]
    );
  };

  const handleCreate = async () => {
    setError('');
    if (!name.trim()) return setError('Please name the group');
    if (selected.length < 1) return setError('Add at least one member');
    setCreating(true);
    try {
      const group = await createGroup(name.trim(), selected.map((m) => m.id));
      onCreated?.(group);
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to create group');
    } finally {
      setCreating(false);
    }
  };

  return (
    <motion.div
      className="cg-overlay"
      onClick={onClose}
      variants={backdropVariant}
      initial="hidden"
      animate="show"
      exit="exit"
    >
      <motion.div
        className="cg-modal"
        onClick={(e) => e.stopPropagation()}
        variants={modalVariant}
        initial="hidden"
        animate="show"
        exit="exit"
      >
        <div className="cg-header">
          <h3>✨ New Group</h3>
          <button className="cg-close" onClick={onClose}>✕</button>
        </div>

        <div className="cg-body">
          <input
            className="cg-input"
            placeholder="Group name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={60}
          />

          {selected.length > 0 && (
            <div className="cg-chips">
              {selected.map((m) => (
                <span key={m.id} className="cg-chip" onClick={() => toggle(m)}>
                  {m.username} ✕
                </span>
              ))}
            </div>
          )}

          <form className="cg-search" onSubmit={search}>
            <input
              className="cg-input"
              placeholder="Search users to add…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <button type="submit" className="cg-search-btn" disabled={searching}>
              {searching ? '⏳' : '🔍'}
            </button>
          </form>

          <div className="cg-results">
            {results.map((u) => {
              const isSel = selected.some((m) => m.id === u.id);
              return (
                <div
                  key={u.id}
                  className={`cg-result ${isSel ? 'selected' : ''}`}
                  onClick={() => toggle(u)}
                >
                  <div className="cg-avatar">{u.username.charAt(0).toUpperCase()}</div>
                  <div className="cg-result-info">
                    <span className="cg-name">{u.username}</span>
                    <span className="cg-email">{u.email}</span>
                  </div>
                  <span className="cg-check">{isSel ? '✓' : '+'}</span>
                </div>
              );
            })}
            {results.length === 0 && (
              <p className="cg-hint">Search and tap users to add them.</p>
            )}
          </div>

          {error && <div className="cg-error">{error}</div>}
        </div>

        <div className="cg-footer">
          <button className="cg-btn-secondary" onClick={onClose} disabled={creating}>
            Cancel
          </button>
          <button className="cg-btn-primary" onClick={handleCreate} disabled={creating}>
            {creating ? 'Creating…' : `Create${selected.length ? ` (${selected.length})` : ''}`}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

export default CreateGroupModal;
