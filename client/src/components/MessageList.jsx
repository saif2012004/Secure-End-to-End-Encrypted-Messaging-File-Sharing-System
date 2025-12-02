import { useEffect, useRef } from 'react';
import '../styles/MessageList.css';

function MessageList({ messages, currentUser }) {
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const formatDate = (timestamp) => {
    const date = new Date(timestamp);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    if (date.toDateString() === today.toDateString()) {
      return 'Today';
    } else if (date.toDateString() === yesterday.toDateString()) {
      return 'Yesterday';
    } else {
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });
    }
  };

  // Group messages by date
  const groupedMessages = messages.reduce((groups, message) => {
    const date = formatDate(message.timestamp);
    if (!groups[date]) {
      groups[date] = [];
    }
    groups[date].push(message);
    return groups;
  }, {});

  return (
    <div className="message-list">
      {Object.keys(groupedMessages).length === 0 ? (
        <div className="no-messages">
          <p>No messages yet</p>
          <span>Start the conversation with an encrypted message 🔒</span>
        </div>
      ) : (
        Object.entries(groupedMessages).map(([date, dateMessages]) => (
          <div key={date}>
            <div className="date-divider">
              <span>{date}</span>
            </div>
            {dateMessages.map((message) => {
              const isOwnMessage = message.senderId === currentUser?.id;

              return (
                <div
                  key={message.id}
                  className={`message ${isOwnMessage ? 'own' : 'other'}`}
                >
                  <div className="message-content">
                    {!isOwnMessage && (
                      <div className="message-avatar">
                        {message.senderUsername?.charAt(0).toUpperCase() || '?'}
                      </div>
                    )}
                    <div className="message-bubble">
                      {message.messageType === 'file' && (
                        <div className="file-message">
                          <span className="file-icon">📎</span>
                          <div className="file-info">
                            <span className="file-name">{message.fileName}</span>
                            <span className="file-size">
                              {(message.fileSize / 1024).toFixed(2)} KB
                            </span>
                          </div>
                        </div>
                      )}
                      <p className="message-text">{message.text}</p>
                      <div className="message-meta">
                        <span className="message-time">
                          {formatTime(message.timestamp)}
                        </span>
                        {isOwnMessage && (
                          <span className="message-status">
                            {message.read ? '✓✓' : message.delivered ? '✓' : '🕐'}
                          </span>
                        )}
                        {message.isEncrypted && (
                          <span className="encryption-badge" title="End-to-end encrypted">
                            🔒
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        ))
      )}
      <div ref={messagesEndRef} />
    </div>
  );
}

export default MessageList;

