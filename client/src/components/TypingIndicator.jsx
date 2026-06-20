import { motion, AnimatePresence } from 'framer-motion';
import { useChatStore } from '../store/chatStore';
import '../styles/TypingIndicator.css';

function TypingIndicator({ userId, username }) {
  const typingUsers = useChatStore((s) => s.typingUsers);
  const isTyping = !!userId && typingUsers.includes(userId);

  return (
    <AnimatePresence>
      {isTyping && (
        <motion.div
          className="typing-indicator"
          initial={{ opacity: 0, y: 12, scale: 0.9 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 8, scale: 0.9 }}
          transition={{ type: 'spring', stiffness: 400, damping: 28 }}
        >
          <div className="typing-avatar">
            {username?.charAt(0).toUpperCase() || '?'}
          </div>
          <div className="typing-bubble">
            <span className="typing-dots" aria-label={`${username || 'User'} is typing`}>
              <span className="dot" />
              <span className="dot" />
              <span className="dot" />
            </span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default TypingIndicator;
