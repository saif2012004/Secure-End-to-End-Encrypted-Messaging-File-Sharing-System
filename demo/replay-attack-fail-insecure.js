// Saif wrote this demo on 2nd Dec night
// This mirrors the previous replay but uses weakDecryptEnvelope (no nonce/seq/timestamp checks).
// Expected result: replay will be ACCEPTED even though it's a duplicate.

import { weakDecryptEnvelope } from '../client/src/services/encryptionService';

const demoSessionKey = new Uint8Array(32).fill(9);

const capturedEnvelope = {
  v: 1,
  sender_id: 'studentA_pubkey_b64',
  recipient_id: 'studentB_id',
  nonce: 'replay_nonce_ab12', // This should have been blocked, but weak decrypt ignores it
  timestamp: Date.now() - 10_000,
  seq: 77,
  payload: 'BASE64_PAYLOAD_CIPHERTEXT_IV_TAG',
};

async function runInsecureReplay() {
  try {
    const first = await weakDecryptEnvelope(capturedEnvelope, demoSessionKey);
    console.log('First decrypt (insecure) plaintext:', first);

    setTimeout(async () => {
      const replayed = await weakDecryptEnvelope(capturedEnvelope, demoSessionKey);
      console.log('Replay accepted (this is insecure):', replayed);
    }, 2000);
  } catch (err) {
    console.error('Unexpected failure in insecure replay demo:', err);
  }
}

runInsecureReplay();
