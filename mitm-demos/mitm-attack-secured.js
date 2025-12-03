// Same idea as the insecure demo, but now the victims sign their ECDH share
// with a long-term ECDSA key + timestamp. MITM swaps keys again, but the
// signature check blows up. Screenshot the "MITM FAILED" line for the report.

import {
  createECDH,
  createHash,
  createSign,
  createVerify,
  generateKeyPairSync,
} from 'crypto';
import WebSocket, { WebSocketServer } from 'ws';

const PORT = 9091; // different port so I can run both demos back-to-back
const MAX_DRIFT_MS = 5_000; // timestamp freshness window
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deriveKey = (secret) =>
  createHash('sha256').update(secret).digest('hex');

// Pretend these are pre-shared identity keys (would be on disk / certificate).
const signingKeys = {
  alice: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  bob: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
};

// Attacker has no access to the above private keys; he only has his own junk key.
const mitmSigner = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const mitm = {
  withAlice: createECDH('prime256v1'),
  withBob: createECDH('prime256v1'),
  stolenKeys: { alice: null, bob: null },
};
mitm.withAlice.generateKeys();
mitm.withBob.generateKeys();

const sockets = { alice: null, bob: null };
let reported = false;

const server = new WebSocketServer({ port: PORT });
console.log(`[setup] Secure demo MITM proxy on ws://localhost:${PORT}`);

server.on('connection', (ws) => {
  let name = 'unknown';
  ws.on('message', (raw) => {
    const msg = JSON.parse(raw);

    if (msg.type === 'hello') {
      name = msg.name;
      sockets[name] = ws;
      console.log(`[wire] ${name} connected (secure flavor).`);
      return;
    }

    if (msg.type === 'pubkey') {
      handleVictimHandshake(name, msg);
    }
  });
});

function signHandshake(name, pubKeyHex, timestamp) {
  const signer = createSign('SHA256');
  signer.update(`${pubKeyHex}|${timestamp}`);
  signer.end();
  return signer.sign(signingKeys[name].privateKey, 'hex');
}

function verifyHandshake(expectedName, msg) {
  const drift = Math.abs(Date.now() - msg.timestamp);
  if (drift > MAX_DRIFT_MS) {
    throw new Error(`timestamp too old (${drift}ms)`);
  }
  const verifier = createVerify('SHA256');
  verifier.update(`${msg.pubKey}|${msg.timestamp}`);
  verifier.end();
  return verifier.verify(signingKeys[expectedName].publicKey, msg.signature, 'hex');
}

function handleVictimHandshake(name, msg) {
  // MITM still computes secrets, but forwarding will fail signature checks.
  if (name === 'alice') {
    const secret = mitm.withAlice.computeSecret(Buffer.from(msg.pubKey, 'hex'));
    mitm.stolenKeys.alice = deriveKey(secret);
    console.log(`[mitm] (secure) tried to steal Alice -> got ${mitm.stolenKeys.alice.slice(0, 24)}...`);

    // Forge a new payload toward Bob with MITM's own pubkey + bogus signature.
    if (sockets.bob) {
      const forgedPub = mitm.withBob.getPublicKey('hex');
      const forgedTs = Date.now();
      const forgedSig = createSign('SHA256')
        .update(`${forgedPub}|${forgedTs}`)
        .sign(mitmSigner.privateKey, 'hex'); // wrong key on purpose

      sockets.bob.send(
        JSON.stringify({
          type: 'pubkey',
          from: 'alice',
          pubKey: forgedPub,
          timestamp: forgedTs,
          signature: forgedSig,
        }),
      );
    }
  } else if (name === 'bob') {
    const secret = mitm.withBob.computeSecret(Buffer.from(msg.pubKey, 'hex'));
    mitm.stolenKeys.bob = deriveKey(secret);
    console.log(`[mitm] (secure) tried to steal Bob   -> got ${mitm.stolenKeys.bob.slice(0, 24)}...`);

    if (sockets.alice) {
      const forgedPub = mitm.withAlice.getPublicKey('hex');
      const forgedTs = Date.now();
      const forgedSig = createSign('SHA256')
        .update(`${forgedPub}|${forgedTs}`)
        .sign(mitmSigner.privateKey, 'hex');

      sockets.alice.send(
        JSON.stringify({
          type: 'pubkey',
          from: 'bob',
          pubKey: forgedPub,
          timestamp: forgedTs,
          signature: forgedSig,
        }),
      );
    }
  }
}

function spinUpVictim(name, expectedPeer) {
  const socket = new WebSocket(`ws://localhost:${PORT}`);
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();

  socket.on('open', async () => {
    socket.send(JSON.stringify({ type: 'hello', name }));
    await delay(50);
    const timestamp = Date.now();
    const pubKeyHex = ecdh.getPublicKey('hex');
    const signature = signHandshake(name, pubKeyHex, timestamp);

    socket.send(
      JSON.stringify({
        type: 'pubkey',
        name,
        pubKey: pubKeyHex,
        timestamp,
        signature,
      }),
    );
  });

  socket.on('message', (raw) => {
    const msg = JSON.parse(raw);
    if (msg.type === 'pubkey') {
      try {
        const ok = verifyHandshake(expectedPeer, msg);
        if (!ok) throw new Error('signature verify returned false');
      } catch (err) {
        if (!reported) {
          reported = true;
          console.log('\nMITM FAILED: Signature verification failed');
          console.log(`[detail] ${expectedPeer} pubkey was tampered -> ${err.message}`);
          console.log('Take a screenshot of this failure for the write-up.\n');
          setTimeout(() => {
            server.close();
            process.exit(0);
          }, 500);
        }
        return;
      }

      // Would only run if the message was legit (not in this demo).
      const shared = ecdh.computeSecret(Buffer.from(msg.pubKey, 'hex'));
      const sessionKey = deriveKey(shared);
      console.log(`[${name}] verified signature and derived ${sessionKey.slice(0, 24)}...`);
    }
  });
}

// Spin up the two secured victims.
spinUpVictim('alice', 'bob');
spinUpVictim('bob', 'alice');
