import { useState, useRef } from 'react';
import { useChatStore } from '../store/chatStore';
import { encryptMessage } from '../utils/crypto';
import '../styles/MessageInput.css';

function MessageInput({ recipientId }) {
  const [message, setMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const { sendMessage } = useChatStore();
  const typingTimeoutRef = useRef(null);

  const handleTyping = (e) => {
    setMessage(e.target.value);

    // TODO: Emit typing indicator via Socket.io
    // socket.emit('typing:start', { recipientId });

    // Clear previous timeout
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }

    // Set typing to false after 2 seconds of inactivity
    typingTimeoutRef.current = setTimeout(() => {
      // socket.emit('typing:stop', { recipientId });
    }, 2000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!message.trim()) {
      return;
    }

    try {
      // NOTE: Placeholder encryption function
      // Members 1 & 2 will implement actual encryption
      const encrypted = await encryptMessage(message, recipientId);

      // Send encrypted message
      await sendMessage({
        recipientId,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        tag: encrypted.tag,
        seq: Date.now(), // Placeholder sequence number
        plaintext: message, // For display only (remove in production!)
        messageType: 'text',
      });

      setMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
      alert('Failed to send message. Please try again.');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className="message-input-container">
      <form onSubmit={handleSubmit} className="message-input-form">
        <div className="input-wrapper">
          <textarea
            value={message}
            onChange={handleTyping}
            onKeyPress={handleKeyPress}
            placeholder="Type an encrypted message..."
            rows={1}
            className="message-textarea"
            disabled={!recipientId}
          />
        </div>
        <button
          type="submit"
          className="btn-send"
          disabled={!message.trim() || !recipientId}
          title="Send encrypted message"
        >
          <span className="send-icon">📤</span>
        </button>
      </form>
      <div className="encryption-notice">
        🔒 Messages are end-to-end encrypted
      </div>
    </div>
  );
}

export default MessageInput;

