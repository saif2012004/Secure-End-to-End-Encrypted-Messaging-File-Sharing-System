import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { getIdentityPublicB64, getPeerIdentity } from '../services/keyExchangeService';
import { computeSafetyNumber } from '../services/safetyNumber';
import { backdropVariant, modalVariant } from '../animations/variants';
import '../styles/SafetyNumberModal.css';

function SafetyNumberModal({ peer, onClose }) {
  const [number, setNumber] = useState(null);
  const [status, setStatus] = useState('loading'); // loading | ready | nokey
  const [verified, setVerified] = useState(
    () => localStorage.getItem(`verified_${peer.id}`) === 'true'
  );

  useEffect(() => {
    let ignore = false;
    (async () => {
      const myPub = await getIdentityPublicB64();
      const peerPub = await getPeerIdentity(peer.id);
      if (ignore) return;
      if (!peerPub) {
        setStatus('nokey');
        return;
      }
      const sn = await computeSafetyNumber(myPub, peerPub);
      if (ignore) return;
      setNumber(sn);
      setStatus('ready');
    })();
    return () => {
      ignore = true;
    };
  }, [peer.id]);

  const toggleVerified = () => {
    const next = !verified;
    setVerified(next);
    localStorage.setItem(`verified_${peer.id}`, String(next));
  };

  return (
    <motion.div
      className="sn-overlay"
      onClick={onClose}
      variants={backdropVariant}
      initial="hidden"
      animate="show"
      exit="exit"
    >
      <motion.div
        className="sn-modal"
        onClick={(e) => e.stopPropagation()}
        variants={modalVariant}
        initial="hidden"
        animate="show"
        exit="exit"
      >
        <div className="sn-header">
          <h3>🛡️ Verify {peer.username}</h3>
          <button className="sn-close" onClick={onClose}>✕</button>
        </div>

        <div className="sn-body">
          <p className="sn-intro">
            Compare this safety number with {peer.username} over a trusted channel
            (in person, a call). If it matches on both devices, your conversation is
            <strong> not being intercepted</strong>.
          </p>

          {status === 'loading' && <div className="sn-spinner" />}

          {status === 'nokey' && (
            <div className="sn-warn">
              No identity key yet for {peer.username}. Open the chat and let key
              exchange complete, then try again.
            </div>
          )}

          {status === 'ready' && (
            <>
              <pre className="sn-number">{number}</pre>
              <div className={`sn-badge ${verified ? 'ok' : ''}`}>
                {verified ? '✓ Marked as verified' : 'Not verified yet'}
              </div>
            </>
          )}
        </div>

        <div className="sn-footer">
          <button className="sn-btn-secondary" onClick={onClose}>Close</button>
          {status === 'ready' && (
            <button
              className={`sn-btn-primary ${verified ? 'unverify' : ''}`}
              onClick={toggleVerified}
            >
              {verified ? 'Mark unverified' : 'Mark as verified'}
            </button>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}

export default SafetyNumberModal;
