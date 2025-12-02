import { useState, useEffect } from 'react';
import { useChatStore } from '../store/chatStore';
import { useAuthStore } from '../store/authStore';
import { useSocketStore } from '../store/socketStore';
import { usersAPI } from '../services/api';
import '../styles/UserSidebar.css';

function UserSidebar() {
  const [users, setUsers] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const { user: currentUser } = useAuthStore();
  const { selectedUser, setSelectedUser, conversations } = useChatStore();
  const { isConnected } = useSocketStore();

  // Load users on mount
  useEffect(() => {
    loadUsers();
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
        // Filter out current user
        const filteredUsers = response.data.users.filter(
          (u) => u.id !== currentUser?.id
        );
        setUsers(filteredUsers);
      }
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    setSearchQuery(e.target.value);
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadUsers();
  };

  const getLastMessage = (userId) => {
    const conversation = conversations.find(
      (c) => c.partner.id === userId
    );
    return conversation?.lastMessage;
  };

  const getUnreadCount = (userId) => {
    const conversation = conversations.find(
      (c) => c.partner.id === userId
    );
    return conversation?.unreadCount || 0;
  };

  return (
    <div className="user-sidebar">
      {/* Sidebar Header */}
      <div className="sidebar-header">
        <div className="user-profile">
          <div className="profile-avatar">
            {currentUser?.username.charAt(0).toUpperCase()}
          </div>
          <div className="profile-info">
            <h3>{currentUser?.username}</h3>
            <p className={`connection-status ${isConnected ? 'connected' : ''}`}>
              {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </p>
          </div>
        </div>
      </div>

      {/* Search Bar */}
      <div className="search-container">
        <form onSubmit={handleSearchSubmit}>
          <input
            type="text"
            placeholder="Search users..."
            value={searchQuery}
            onChange={handleSearch}
            className="search-input"
          />
          <button type="submit" className="search-btn" disabled={loading}>
            {loading ? '⏳' : '🔍'}
          </button>
        </form>
      </div>

      {/* Conversations List */}
      <div className="conversations-list">
        {searchQuery.trim() ? (
          // Search Results
          <>
            {loading ? (
              <div className="loading-state">
                <p>Searching...</p>
              </div>
            ) : users.length > 0 ? (
              users.map((user) => (
                <div
                  key={user.id}
                  className={`conversation-item ${
                    selectedUser?.id === user.id ? 'active' : ''
                  }`}
                  onClick={() => setSelectedUser(user)}
                >
                  <div className="conversation-avatar">
                    {user.username.charAt(0).toUpperCase()}
                  </div>
                  <div className="conversation-info">
                    <div className="conversation-header">
                      <h4>{user.username}</h4>
                      <span className={`status-indicator ${user.isOnline ? 'online' : ''}`}>
                        {user.isOnline ? '🟢' : '⚫'}
                      </span>
                    </div>
                    <p className="conversation-preview">
                      {user.email}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <p>No users found</p>
                <span>Try a different search</span>
              </div>
            )}
          </>
        ) : conversations.length > 0 ? (
          // Recent Conversations
          conversations.map((conversation) => {
            const partner = conversation.partner;
            const lastMessage = conversation.lastMessage;
            const unreadCount = conversation.unreadCount || 0;

            return (
              <div
                key={partner.id}
                className={`conversation-item ${
                  selectedUser?.id === partner.id ? 'active' : ''
                }`}
                onClick={() => setSelectedUser(partner)}
              >
                <div className="conversation-avatar">
                  {partner.username.charAt(0).toUpperCase()}
                  {unreadCount > 0 && (
                    <span className="unread-badge">{unreadCount}</span>
                  )}
                </div>
                <div className="conversation-info">
                  <div className="conversation-header">
                    <h4>{partner.username}</h4>
                    <span className={`status-indicator ${partner.isOnline ? 'online' : ''}`}>
                      {partner.isOnline ? '🟢' : '⚫'}
                    </span>
                  </div>
                  {lastMessage && (
                    <p className={`conversation-preview ${unreadCount > 0 ? 'unread' : ''}`}>
                      {lastMessage.messageType === 'file'
                        ? '📎 File'
                        : lastMessage.text.substring(0, 30) +
                          (lastMessage.text.length > 30 ? '...' : '')}
                    </p>
                  )}
                </div>
              </div>
            );
          })
        ) : (
          <div className="empty-state">
            <p>No conversations yet</p>
            <span>Search for users to start chatting</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default UserSidebar;

