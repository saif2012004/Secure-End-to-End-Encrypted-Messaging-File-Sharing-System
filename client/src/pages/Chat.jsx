import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuthStore } from '../store/authStore';
import { useChatStore } from '../store/chatStore';
import { useGroupStore } from '../store/groupStore';
import { useSocketStore } from '../store/socketStore';
import UserSidebar from '../components/UserSidebar';
import MessageList from '../components/MessageList';
import MessageInput from '../components/MessageInput';
import TypingIndicator from '../components/TypingIndicator';
import FileUpload from '../components/FileUpload';
import SafetyNumberModal from '../components/SafetyNumberModal';
import GroupManageModal from '../components/GroupManageModal';
import { waitForSessionKey, getSessionKey } from '../services/keyExchangeService';
import { listContainer, listItem, spring } from '../animations/variants';
import '../styles/Chat.css';

const FEATURES = [
  { icon: '🔒', label: 'End-to-end encrypted' },
  { icon: '⚡', label: 'Real-time messaging' },
  { icon: '📎', label: 'Secure file sharing' },
];

function Chat() {
  const { user, logout } = useAuthStore();
  const { selectedUser, messages, isLoadingMessages, messagesError, fetchConversations } = useChatStore();
  const { selectedGroup, groupMessages, isLoadingGroup } = useGroupStore();
  const { socket, connect, disconnect, isConnected } = useSocketStore();
  const [showFileUpload, setShowFileUpload] = useState(false);
  const [uploadSessionKey, setUploadSessionKey] = useState(null);
  const [showVerify, setShowVerify] = useState(false);
  const [showGroupManage, setShowGroupManage] = useState(false);

  // Connect to Socket.io on mount + load recent conversations
  useEffect(() => {
    connect();
    fetchConversations();

    return () => {
      disconnect();
    };
  }, [connect, disconnect, fetchConversations]);

  const handleLogout = () => {
    disconnect();
    logout();
  };

  useEffect(() => {
    let ignore = false;
    (async () => {
      if (!showFileUpload || !selectedUser) return;
      // Try to obtain session key for file encryption
      const keyBytes =
        (await getSessionKey(selectedUser.id)) ||
        (await waitForSessionKey(selectedUser.id, selectedUser.username, 5000));
      if (!ignore) setUploadSessionKey(keyBytes || null);
      if (!keyBytes) {
        alert('Session key not ready; complete key exchange first.');
        setShowFileUpload(false);
      }
    })();
    return () => { ignore = true; };
  }, [showFileUpload, selectedUser]);

  return (
    <div className="chat-container">
      {/* User Sidebar */}
      <UserSidebar />

      {/* Chat Area */}
      <div className="chat-main">
        {selectedGroup ? (
          <>
            {/* Group Header */}
            <motion.div
              className="chat-header"
              initial={{ y: -20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={spring}
            >
              <div className="chat-user-info">
                <motion.div
                  className="user-avatar"
                  key={selectedGroup.id}
                  initial={{ scale: 0, rotate: -90 }}
                  animate={{ scale: 1, rotate: 0 }}
                  transition={spring}
                  style={{ background: selectedGroup.avatarColor }}
                >
                  👥
                </motion.div>
                <div className="user-details">
                  <h3>{selectedGroup.name}</h3>
                  <p className="status">
                    {(selectedGroup.members?.length || 0)} members ·{' '}
                    {(selectedGroup.members || [])
                      .map((m) => m.username)
                      .slice(0, 3)
                      .join(', ')}
                    {(selectedGroup.members?.length || 0) > 3 ? '…' : ''}
                  </p>
                </div>
              </div>
              <div className="chat-actions">
                <motion.button className="btn-icon" onClick={() => setShowGroupManage(true)} title="Manage group"
                  whileHover={{ y: -2, scale: 1.08 }} whileTap={{ scale: 0.92 }}>
                  ⚙️
                </motion.button>
                <motion.button className="btn-icon" onClick={handleLogout} title="Logout"
                  whileHover={{ y: -2, scale: 1.08 }} whileTap={{ scale: 0.92 }}>
                  🚪
                </motion.button>
              </div>
            </motion.div>

            <AnimatePresence>
              {showGroupManage && (
                <GroupManageModal onClose={() => setShowGroupManage(false)} />
              )}
            </AnimatePresence>

            {isLoadingGroup ? (
              <div className="loading-messages">
                <div className="spinner"></div>
                <p>Loading messages...</p>
              </div>
            ) : (
              <MessageList messages={groupMessages} currentUser={user} />
            )}

            <MessageInput group={selectedGroup} />

            <motion.div
              className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={spring}
            >
              {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </motion.div>
          </>
        ) : selectedUser ? (
          <>
            {/* Chat Header */}
            <motion.div
              className="chat-header"
              initial={{ y: -20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={spring}
            >
              <div className="chat-user-info">
                <motion.div
                  className="user-avatar"
                  key={selectedUser.id}
                  initial={{ scale: 0, rotate: -90 }}
                  animate={{ scale: 1, rotate: 0 }}
                  transition={spring}
                >
                  {selectedUser.username.charAt(0).toUpperCase()}
                </motion.div>
                <div className="user-details">
                  <h3>{selectedUser.username}</h3>
                  <p className={`status ${selectedUser.isOnline ? 'online' : 'offline'}`}>
                    {selectedUser.isOnline ? '🟢 Online' : '⚫ Offline'}
                  </p>
                </div>
              </div>
              <div className="chat-actions">
                <motion.button
                  className="btn-icon"
                  onClick={() => setShowVerify(true)}
                  title="Verify safety number"
                  whileHover={{ y: -2, scale: 1.08 }}
                  whileTap={{ scale: 0.92 }}
                >
                  🛡️
                </motion.button>
                <motion.button
                  className="btn-icon"
                  onClick={() => setShowFileUpload(!showFileUpload)}
                  title="Upload file"
                  whileHover={{ y: -2, scale: 1.08 }}
                  whileTap={{ scale: 0.92 }}
                >
                  📎
                </motion.button>
                <motion.button
                  className="btn-icon"
                  onClick={handleLogout}
                  title="Logout"
                  whileHover={{ y: -2, scale: 1.08 }}
                  whileTap={{ scale: 0.92 }}
                >
                  🚪
                </motion.button>
              </div>
            </motion.div>

            {/* File Upload Modal */}
            <AnimatePresence>
              {showFileUpload && (
                <FileUpload
                  recipientId={selectedUser.id}
                  sessionKeyBytes={uploadSessionKey}
                  onClose={() => setShowFileUpload(false)}
                />
              )}
            </AnimatePresence>

            {/* Safety Number / fingerprint verification */}
            <AnimatePresence>
              {showVerify && (
                <SafetyNumberModal
                  peer={selectedUser}
                  onClose={() => setShowVerify(false)}
                />
              )}
            </AnimatePresence>

            {/* Messages */}
            {isLoadingMessages ? (
              <div className="loading-messages">
                <div className="spinner"></div>
                <p>Loading messages...</p>
              </div>
            ) : messagesError ? (
              <div className="error-messages">
                <p>❌ {messagesError}</p>
                <button onClick={() => window.location.reload()}>Retry</button>
              </div>
            ) : (
              <MessageList messages={messages} currentUser={user} />
            )}

            {/* Live typing indicator */}
            <TypingIndicator userId={selectedUser.id} username={selectedUser.username} />

            {/* Message Input */}
            <MessageInput recipientId={selectedUser.id} />

            {/* Connection Status */}
            <motion.div
              className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={spring}
            >
              {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </motion.div>
          </>
        ) : (
          <div className="no-chat-selected">
            <motion.div
              className="welcome-message"
              variants={listContainer}
              initial="hidden"
              animate="show"
            >
              <motion.h2 variants={listItem}>👋 Welcome, {user?.username}!</motion.h2>
              <motion.p variants={listItem}>
                Select a user from the sidebar to start chatting
              </motion.p>
              <div className="features-list">
                {FEATURES.map((f) => (
                  <motion.div
                    key={f.label}
                    className="feature-item"
                    variants={listItem}
                    whileHover={{ x: 6, scale: 1.02 }}
                  >
                    <span className="feature-icon">{f.icon}</span>
                    <span>{f.label}</span>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Chat;
