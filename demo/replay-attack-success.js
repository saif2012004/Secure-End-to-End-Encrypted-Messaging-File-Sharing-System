// Saif wrote this demo on 2nd Dec night
// This script simulates an attacker replaying a captured envelope.
// Expected result: parseAndDecryptEnvelope should REJECT the replay because nonce + seq were already seen.

import { parseAndDecryptEnvelope } from '../client/src/services/encryptionService';

// Fake session key (32 bytes). In a real test, share this between sender/receiver.
const demoSessionKey = new Uint8Array(32).fill(7);

// Captured envelope from the "first delivery"
const capturedEnvelope = {
  v: 1,
  sender_id: 'studentA_pubkey_b64',
  recipient_id: 'studentB_id',
  nonce: '8f3a1c9dZREPLAYBASE64', // This will be rejected because nonce 8f3a... was already seen at timestamp 1733555500000
  timestamp: Date.now(),
  seq: 42,
  payload: 'BASE64_PAYLOAD_CIPHERTEXT_IV_TAG',
};

async function runReplay() {
  // First acceptance (store nonce + seq) — normally done by the receiver app once.
  await parseAndDecryptEnvelope(capturedEnvelope, demoSessionKey).catch((err) => {
    console.error('Initial parse (should pass in a real run) failed:', err.message);
  });

  // Attacker waits 2 seconds then replays the exact same envelope.
  setTimeout(async () => {
    try {
      console.log('Replaying captured envelope after 2s...');
      await parseAndDecryptEnvelope(capturedEnvelope, demoSessionKey);
      console.error('Unexpected success: replay should have been blocked');
    } catch (err) {
      if (String(err.message || err).includes('REPLAY_ATTACK_DETECTED')) {
        console.log('Replay correctly rejected with REPLAY_ATTACK_DETECTED');
      } else {
        console.error('Replay failed with a different error:', err);
      }
    }
  }, 2000);
}

runReplay();
