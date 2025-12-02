import { useState, useEffect } from 'react';
import { useAuthStore } from '../store/authStore';
import { useChatStore } from '../store/chatStore';
import { useSocketStore } from '../store/socketStore';
import UserSidebar from '../components/UserSidebar';
import MessageList from '../components/MessageList';
import MessageInput from '../components/MessageInput';
import FileUpload from '../components/FileUpload';
import '../styles/Chat.css';

function Chat() {
  const { user, logout } = useAuthStore();
  const { selectedUser, messages, isLoadingMessages, messagesError } = useChatStore();
  const { socket, connect, disconnect, isConnected } = useSocketStore();
  const [showFileUpload, setShowFileUpload] = useState(false);

  // Connect to Socket.io on mount
  useEffect(() => {
    connect();

    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  const handleLogout = () => {
    disconnect();
    logout();
  };

  return (
    <div className="chat-container">
      {/* User Sidebar */}
      <UserSidebar />

      {/* Chat Area */}
      <div className="chat-main">
        {selectedUser ? (
          <>
            {/* Chat Header */}
            <div className="chat-header">
              <div className="chat-user-info">
                <div className="user-avatar">
                  {selectedUser.username.charAt(0).toUpperCase()}
                </div>
                <div className="user-details">
                  <h3>{selectedUser.username}</h3>
                  <p className={`status ${selectedUser.isOnline ? 'online' : 'offline'}`}>
                    {selectedUser.isOnline ? '🟢 Online' : '⚫ Offline'}
                  </p>
                </div>
              </div>
              <div className="chat-actions">
                <button
                  className="btn-icon"
                  onClick={() => setShowFileUpload(!showFileUpload)}
                  title="Upload file"
                >
                  📎
                </button>
                <button className="btn-icon" onClick={handleLogout} title="Logout">
                  🚪
                </button>
              </div>
            </div>

            {/* File Upload Modal */}
            {showFileUpload && (
              <FileUpload
                recipientId={selectedUser.id}
                onClose={() => setShowFileUpload(false)}
              />
            )}

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

            {/* Message Input */}
            <MessageInput recipientId={selectedUser.id} />

            {/* Connection Status */}
            <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
              {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </div>
          </>
        ) : (
          <div className="no-chat-selected">
            <div className="welcome-message">
              <h2>👋 Welcome, {user?.username}!</h2>
              <p>Select a user from the sidebar to start chatting</p>
              <div className="features-list">
                <div className="feature-item">
                  <span className="feature-icon">🔒</span>
                  <span>End-to-end encrypted</span>
                </div>
                <div className="feature-item">
                  <span className="feature-icon">⚡</span>
                  <span>Real-time messaging</span>
                </div>
                <div className="feature-item">
                  <span className="feature-icon">📎</span>
                  <span>Secure file sharing</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Chat;

