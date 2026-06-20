import { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useChatStore } from '../store/chatStore';
import { useGroupStore } from '../store/groupStore';
import { useSocketStore } from '../store/socketStore';
import '../styles/MessageInput.css';

function MessageInput({ recipientId, group }) {
  const [message, setMessage] = useState('');
  const [sending, setSending] = useState(false);
  const { sendMessage } = useChatStore();
  const { sendGroupMessage } = useGroupStore();
  const { sendTypingStart, sendTypingStop } = useSocketStore();
  const typingTimeoutRef = useRef(null);
  const isTypingRef = useRef(false);
  const isGroup = !!group;

  const stopTyping = () => {
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = null;
    }
    if (isTypingRef.current) {
      isTypingRef.current = false;
      if (recipientId) sendTypingStop(recipientId);
    }
  };

  useEffect(() => {
    return () => stopTyping();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recipientId]);

  const handleTyping = (e) => {
    setMessage(e.target.value);
    if (isGroup || !recipientId) return; // typing indicators only for 1-1

    if (!isTypingRef.current) {
      isTypingRef.current = true;
      sendTypingStart(recipientId);
    }
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      isTypingRef.current = false;
      sendTypingStop(recipientId);
    }, 2500);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!message.trim() || sending) return;

    stopTyping();
    const text = message;
    setSending(true);
    try {
      if (isGroup) {
        await sendGroupMessage(text);
      } else {
        await sendMessage({ recipientId, plaintext: text, messageType: 'text' });
      }
      setMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
      alert(error.message || 'Failed to send message. Please try again.');
    } finally {
      setSending(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const disabled = isGroup ? false : !recipientId;

  return (
    <div className="message-input-container">
      <form onSubmit={handleSubmit} className="message-input-form">
        <div className="input-wrapper">
          <textarea
            value={message}
            onChange={handleTyping}
            onKeyPress={handleKeyPress}
            placeholder={isGroup ? 'Message the group…' : 'Type an encrypted message...'}
            rows={1}
            className="message-textarea"
            disabled={disabled}
          />
        </div>
        <motion.button
          type="submit"
          className="btn-send"
          disabled={!message.trim() || disabled || sending}
          title="Send encrypted message"
          whileHover={{ y: -2, scale: 1.03 }}
          whileTap={{ scale: 0.95 }}
        >
          <span className="send-icon">{sending ? '…' : 'Send'}</span>
        </motion.button>
      </form>
      <div className="encryption-notice">
        {isGroup ? 'Encrypted individually for each member' : 'Messages are end-to-end encrypted'}
      </div>
    </div>
  );
}

export default MessageInput;
