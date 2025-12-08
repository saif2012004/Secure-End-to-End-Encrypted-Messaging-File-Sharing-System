// Quick + dirty MITM demo for the report.
// Run: `npm install ws` once, then `node mitm-demos/mitm-attack-insecure.js`.
// Take a screenshot of the console once the "MITM SUCCESS" line shows up.
// This script sets up a fake "chat server" that is actually the attacker.
// Alice and Bob think they're doing plain ECDH over WebSockets, but I swap their keys.

import { createECDH, createHash } from 'crypto';
import WebSocket, { WebSocketServer } from 'ws';

const PORT = 9090; // easy to remember for the demo
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deriveKey = (secret) =>
  createHash('sha256').update(secret).digest('hex'); // stretch DH output to a readable hex key

// MITM holds two ECDH pairs: one per victim.
const mitm = {
  withAlice: createECDH('prime256v1'),
  withBob: createECDH('prime256v1'),
  stolenKeys: { alice: null, bob: null },
};
mitm.withAlice.generateKeys();
mitm.withBob.generateKeys();

const sockets = { alice: null, bob: null };
const victimsDerived = { alice: null, bob: null };
let alreadyReported = false;

const server = new WebSocketServer({ port: PORT });
console.log(`[setup] MITM proxy listening on ws://localhost:${PORT}`);

server.on('connection', (ws) => {
  let name = 'unknown';

  ws.on('message', (raw) => {
    const msg = JSON.parse(raw);

    if (msg.type === 'hello') {
      name = msg.name;
      sockets[name] = ws;
      console.log(`[wire] ${name} connected (thinks this is the honest relay).`);
      return;
    }

    if (msg.type === 'pubkey') {
      handleVictimPubkey(name, msg.pubKey);
      return;
    }
  });
});

function handleVictimPubkey(name, victimPubHex) {
  if (name === 'alice') {
    const stolenSecret = mitm.withAlice.computeSecret(Buffer.from(victimPubHex, 'hex'));
    mitm.stolenKeys.alice = deriveKey(stolenSecret);
    console.log(`[mitm] Grabbed Alice's DH share -> derived key ${mitm.stolenKeys.alice.slice(0, 24)}...`);

    // Forward to Bob but swap in MITM's own pubkey (classic downgrade).
    if (sockets.bob) {
      sockets.bob.send(
        JSON.stringify({
          type: 'pubkey',
          from: 'alice',
          pubKey: mitm.withBob.getPublicKey('hex'),
        }),
      );
    }
  } else if (name === 'bob') {
    const stolenSecret = mitm.withBob.computeSecret(Buffer.from(victimPubHex, 'hex'));
    mitm.stolenKeys.bob = deriveKey(stolenSecret);
    console.log(`[mitm] Grabbed Bob's DH share   -> derived key ${mitm.stolenKeys.bob.slice(0, 24)}...`);

    // Forward to Alice but again swap the attacker pubkey.
    if (sockets.alice) {
      sockets.alice.send(
        JSON.stringify({
          type: 'pubkey',
          from: 'bob',
          pubKey: mitm.withAlice.getPublicKey('hex'),
        }),
      );
    }
  }

  maybeReport();
}

function maybeReport() {
  if (alreadyReported) return;
  if (
    mitm.stolenKeys.alice &&
    mitm.stolenKeys.bob &&
    victimsDerived.alice &&
    victimsDerived.bob
  ) {
    alreadyReported = true;
    console.log('\nMITM SUCCESS: Derived session key with Alice: ' + mitm.stolenKeys.alice);
    console.log('MITM SUCCESS: Derived session key with Bob:   ' + mitm.stolenKeys.bob);
    console.log(
      `[weirdness] Alice's key === Bob's key? ${
        victimsDerived.alice === victimsDerived.bob ? 'yes (they were both tricked!)' : 'no, two tunnels to me'
      }`,
    );
    console.log('Grab a screenshot here for the report.\n');

    setTimeout(() => {
      server.close();
      process.exit(0);
    }, 500);
  }
}

// Victim-side logic: bare-bones ECDH with zero authenticity checks.
function spinUpVictim(name) {
  const socket = new WebSocket(`ws://localhost:${PORT}`);
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();

  socket.on('open', async () => {
    socket.send(JSON.stringify({ type: 'hello', name }));
    // Tiny delay just so the console output is more linear.
    await delay(50);
    socket.send(
      JSON.stringify({
        type: 'pubkey',
        name,
        pubKey: ecdh.getPublicKey('hex'),
      }),
    );
  });

  socket.on('message', (raw) => {
    const msg = JSON.parse(raw);
    if (msg.type === 'pubkey') {
      const shared = ecdh.computeSecret(Buffer.from(msg.pubKey, 'hex'));
      const sessionKey = deriveKey(shared);
      victimsDerived[name] = sessionKey;
      console.log(
        `[${name}] thinks session key is ${sessionKey.slice(0, 24)}... (using pubkey claimed from ${msg.from})`,
      );
      maybeReport();
    }
  });
}

// Fire up the two naive clients.
spinUpVictim('alice');
spinUpVictim('bob');
