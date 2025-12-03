// Saif wrote this demo on 2nd Dec night (updated to run in Node only, no browser deps)
// This script simulates a receiver with replay protection enabled.
// First delivery is accepted (stores nonce+seq), replay is rejected with REPLAY_ATTACK_DETECTED.

const FRESHNESS_MS = 60_000; // ±60s window like the client
const replayState = new Map(); // key -> { lastSeq, nonces:Set }

function isFresh(ts) {
  const delta = Math.abs(Date.now() - Number(ts));
  return delta <= FRESHNESS_MS;
}

async function parseAndDecryptEnvelope(envelope, sessionKeyBytes) {
  // sessionKeyBytes is unused here; this is a structural demo.
  const env = envelope || {};
  if (!env.nonce || typeof env.seq !== 'number' || !env.sender_id) {
    throw new Error('Envelope validation failed: missing fields');
  }
  if (!isFresh(env.timestamp || Date.now())) {
    throw new Error('REPLAY_ATTACK_DETECTED');
  }

  const key = env.sender_id; // scope replay tracking to sender identity
  const state = replayState.get(key) || { lastSeq: -1, nonces: new Set() };

  if (state.nonces.has(env.nonce)) {
    throw new Error('REPLAY_ATTACK_DETECTED');
  }
  if (env.seq <= state.lastSeq) {
    throw new Error('REPLAY_ATTACK_DETECTED');
  }

  state.nonces.add(env.nonce);
  state.lastSeq = env.seq;
  replayState.set(key, state);

  // We skip real AES-GCM; just return a mocked plaintext to show flow.
  return `PLAINTEXT(${env.payload})`;
}

// Fake session key (32 bytes). In a real test, share this between sender/receiver.
const demoSessionKey = new Uint8Array(32).fill(7);

// Captured envelope from the "first delivery"
const capturedEnvelope = {
  v: 1,
  sender_id: 'studentA_pubkey_b64',
  recipient_id: 'studentB_id',
  nonce: '8f3a1c9dZREPLAYBASE64', // This will be rejected on replay
  timestamp: Date.now(),
  seq: 42,
  payload: 'BASE64_PAYLOAD_CIPHERTEXT_IV_TAG',
};

async function runReplay() {
  try {
    const first = await parseAndDecryptEnvelope(capturedEnvelope, demoSessionKey);
    console.log('Initial delivery accepted, plaintext:', first);
  } catch (err) {
    console.error('Initial parse failed (should pass in a real run):', err.message);
  }

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
