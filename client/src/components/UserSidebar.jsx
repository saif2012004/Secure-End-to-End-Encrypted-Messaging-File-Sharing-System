import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useChatStore } from '../store/chatStore';
import { useGroupStore } from '../store/groupStore';
import { useAuthStore } from '../store/authStore';
import { useSocketStore } from '../store/socketStore';
import { usersAPI } from '../services/api';
import CreateGroupModal from './CreateGroupModal';
import { listContainer, listItem, spring } from '../animations/variants';
import '../styles/UserSidebar.css';

function UserSidebar() {
  const [users, setUsers] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const { user: currentUser } = useAuthStore();
  const { selectedUser, setSelectedUser, conversations } = useChatStore();
  const { groups, selectedGroup, selectGroup, fetchGroups, unreadByGroup } = useGroupStore();
  const { isConnected } = useSocketStore();

  useEffect(() => {
    loadUsers();
    fetchGroups();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadUsers = async () => {
    if (!searchQuery.trim()) {
      setUsers([]);
      return;
    }
    setLoading(true);
    try {
      const response = await usersAPI.searchUsers(searchQuery);
      if (response.success) {
        setUsers(response.data.users.filter((u) => u.id !== currentUser?.id));
      }
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadUsers();
  };

  const pickUser = (user) => {
    useGroupStore.getState().clearSelectedGroup();
    setSelectedUser(user);
  };

  const pickGroup = (group) => {
    useChatStore.setState({ selectedUser: null });
    selectGroup(group);
  };

  const renderUserItem = (item, { isActive, onClick, preview, unreadCount = 0, online }) => (
    <motion.div
      key={item.id}
      layout
      variants={listItem}
      initial="hidden"
      animate="show"
      exit="exit"
      whileHover={{ x: 4 }}
      whileTap={{ scale: 0.98 }}
      transition={spring}
      className={`conversation-item ${isActive ? 'active' : ''}`}
      onClick={onClick}
    >
      <div className="conversation-avatar">
        {item.username.charAt(0).toUpperCase()}
        {unreadCount > 0 && <span className="unread-badge">{unreadCount}</span>}
      </div>
      <div className="conversation-info">
        <div className="conversation-header">
          <h4>{item.username}</h4>
          <span className={`status-indicator ${online ? 'online' : ''}`}>{online ? '🟢' : '⚫'}</span>
        </div>
        <p className={`conversation-preview ${unreadCount > 0 ? 'unread' : ''}`}>{preview}</p>
      </div>
    </motion.div>
  );

  return (
    <div className="user-sidebar">
      <div className="sidebar-header">
        <div className="user-profile">
          <motion.div
            className="profile-avatar"
            initial={{ scale: 0, rotate: -90 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={spring}
          >
            {currentUser?.username.charAt(0).toUpperCase()}
          </motion.div>
          <div className="profile-info">
            <h3>{currentUser?.username}</h3>
            <p className={`connection-status ${isConnected ? 'connected' : ''}`}>
              {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </p>
          </div>
        </div>
      </div>

      <div className="search-container">
        <form onSubmit={handleSearchSubmit}>
          <input
            type="text"
            placeholder="Search users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
          <motion.button
            type="submit"
            className="search-btn"
            disabled={loading}
            whileHover={{ scale: 1.08, rotate: -6 }}
            whileTap={{ scale: 0.9 }}
          >
            {loading ? '⏳' : '🔍'}
          </motion.button>
        </form>
      </div>

      <motion.div className="conversations-list" variants={listContainer} initial="hidden" animate="show">
        {/* Groups section */}
        {!searchQuery.trim() && (
          <>
            <div className="sidebar-section">
              <span>Groups</span>
              <motion.button
                className="new-group-btn"
                onClick={() => setShowCreateGroup(true)}
                whileHover={{ scale: 1.12, rotate: 90 }}
                whileTap={{ scale: 0.9 }}
                title="New group"
              >
                ＋
              </motion.button>
            </div>
            <AnimatePresence mode="popLayout">
              {groups.map((g) => {
                const unread = unreadByGroup[g.id] || 0;
                return (
                  <motion.div
                    key={g.id}
                    layout
                    variants={listItem}
                    initial="hidden"
                    animate="show"
                    exit="exit"
                    whileHover={{ x: 4 }}
                    whileTap={{ scale: 0.98 }}
                    transition={spring}
                    className={`conversation-item ${selectedGroup?.id === g.id ? 'active' : ''}`}
                    onClick={() => pickGroup(g)}
                  >
                    <div className="conversation-avatar group" style={{ background: g.avatarColor }}>
                      👥
                      {unread > 0 && <span className="unread-badge">{unread}</span>}
                    </div>
                    <div className="conversation-info">
                      <div className="conversation-header">
                        <h4>{g.name}</h4>
                      </div>
                      <p className="conversation-preview">{(g.members?.length || 0)} members</p>
                    </div>
                  </motion.div>
                );
              })}
            </AnimatePresence>
            {groups.length === 0 && (
              <p className="sidebar-empty-hint">No groups yet — tap ＋ to create one.</p>
            )}
            <div className="sidebar-section"><span>Direct messages</span></div>
          </>
        )}

        {/* Direct messages / search results */}
        {searchQuery.trim() ? (
          loading ? (
            <div className="loading-state"><p>Searching...</p></div>
          ) : users.length > 0 ? (
            <AnimatePresence mode="popLayout">
              {users.map((u) =>
                renderUserItem(u, {
                  isActive: selectedUser?.id === u.id,
                  onClick: () => pickUser(u),
                  preview: u.email,
                  online: u.isOnline,
                })
              )}
            </AnimatePresence>
          ) : (
            <motion.div className="empty-state" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <p>No users found</p>
              <span>Try a different search</span>
            </motion.div>
          )
        ) : conversations.length > 0 ? (
          <AnimatePresence mode="popLayout">
            {conversations.map((conversation) => {
              const partner = conversation.partner;
              const lastMessage = conversation.lastMessage;
              const unreadCount = conversation.unreadCount || 0;
              const preview = lastMessage
                ? lastMessage.messageType === 'file'
                  ? '📎 File'
                  : lastMessage.text.substring(0, 30) + (lastMessage.text.length > 30 ? '...' : '')
                : '';
              return renderUserItem(partner, {
                isActive: selectedUser?.id === partner.id,
                onClick: () => pickUser(partner),
                preview,
                unreadCount,
                online: partner.isOnline,
              });
            })}
          </AnimatePresence>
        ) : (
          <motion.div className="empty-state" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <p>No conversations yet</p>
            <span>Search for users to start chatting</span>
          </motion.div>
        )}
      </motion.div>

      <AnimatePresence>
        {showCreateGroup && (
          <CreateGroupModal
            onClose={() => setShowCreateGroup(false)}
            onCreated={(g) => pickGroup(g)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

export default UserSidebar;
