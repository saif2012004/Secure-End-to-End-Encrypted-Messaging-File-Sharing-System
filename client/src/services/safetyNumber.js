// Safety number (a.k.a. security code / fingerprint) for MITM detection.
// Both peers independently compute the SAME number from the two identity public
// keys. If the numbers match (compared out-of-band), there is no man-in-the-middle.

const enc = new TextEncoder();

async function sha256(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

// Turn a public key string into a stable 30-digit fingerprint, Signal-style:
// iterated hashing then mapping 5-byte chunks to 5-digit groups.
async function fingerprintFor(pubB64) {
  let data = enc.encode(pubB64);
  // a few hash iterations to slow brute-force preimage attempts
  for (let i = 0; i < 1024; i++) {
    data = await sha256(data);
  }
  const groups = [];
  for (let i = 0; i < 30; i += 5) {
    // take 5 bytes -> a number -> 5 decimal digits
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 256 + data[i + j];
    groups.push(String(n % 100000).padStart(5, '0'));
  }
  return groups; // 6 groups of 5 digits
}

/**
 * Compute the combined safety number for two identity public keys.
 * Order-independent (both sides get the same value) by sorting the keys.
 * @returns {Promise<string>} formatted as 12 groups of 5 digits
 */
export async function computeSafetyNumber(myPubB64, peerPubB64) {
  if (!myPubB64 || !peerPubB64) return null;
  const [a, b] = [myPubB64, peerPubB64].sort();
  const [fa, fb] = await Promise.all([fingerprintFor(a), fingerprintFor(b)]);
  const groups = [...fa, ...fb]; // 12 groups
  // format as 4 rows of 3 groups for readability
  const rows = [];
  for (let i = 0; i < groups.length; i += 3) {
    rows.push(groups.slice(i, i + 3).join(' '));
  }
  return rows.join('\n');
}
