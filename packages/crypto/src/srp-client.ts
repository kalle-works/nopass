/**
 * SRP-6a client implementation — compatible with the Rust `srp` crate 0.6.x.
 *
 * The `secure-remote-password` npm package uses a different `k` formula
 * (g is NOT padded to N's length), while the Rust `srp` crate uses
 * k = H(N | PAD(g, N_len)). This causes every session to fail.
 *
 * This module reimplements the SRP-6a client math from scratch using the
 * EXACT formulas from the Rust `srp` crate 0.6.x so the two sides interoperate:
 *
 *   k  = SHA256(N_bytes | PAD(g_bytes, len(N)))
 *   u  = SHA256(A_bytes | B_bytes)           — minimal, no padding
 *   S  = (B - k*g^x)^(a + u*x)  mod N
 *   M1 = SHA256(A_bytes | B_bytes | S_bytes) — uses raw S, not RFC 5054
 *   M2 = SHA256(A_bytes | M1 | S_bytes)
 *
 * Private key: x = SHA256(s_bytes | SHA256(I + ':' + P))
 * Verifier:    v = g^x mod N
 */

import { sha256 } from "@noble/hashes/sha2.js";

// ── G_2048 group parameters (RFC 3526 / RFC 5054 §A.2) ──────────────────────

const N_HEX =
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
  "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
  "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
  "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
  "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
  "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
  "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
  "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

const N = BigInt("0x" + N_HEX);
const G = 2n;
const N_BYTES = N_HEX.length / 2; // 256

// ── Byte/BigInt helpers ──────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) hex = "0" + hex;
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBase64(hex: string): string {
  const bytes = hexToBytes(hex);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToHex(b64: string): string {
  const s = atob(b64);
  let hex = "";
  for (let i = 0; i < s.length; i++) hex += s.charCodeAt(i).toString(16).padStart(2, "0");
  return hex;
}

/** BigInt → minimal big-endian bytes (no leading zeros, unless value is 0) */
function bigIntToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(1);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return hexToBytes(hex);
}

/** Minimal big-endian bytes → BigInt */
function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + bytesToHex(bytes));
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function getRandomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(buf);
  } else {
    // Node.js: fall back to require('crypto')
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require("crypto") as { randomFillSync: (b: Uint8Array) => void };
    nodeCrypto.randomFillSync(buf);
  }
  return buf;
}

// ── SRP group constants (computed once) ─────────────────────────────────────

/** k = SHA256(N_bytes | PAD(g_bytes, N_BYTES)) — Rust srp 0.6.x formula */
function computeK(): bigint {
  const nBytes = hexToBytes(N_HEX);
  const gBytes = bigIntToBytes(G);
  const padded = new Uint8Array(N_BYTES); // zero-filled
  padded.set(gBytes, N_BYTES - gBytes.length); // right-align g
  const input = new Uint8Array(N_BYTES + N_BYTES);
  input.set(nBytes, 0);
  input.set(padded, N_BYTES);
  return bytesToBigInt(sha256(input));
}

const K_CONST = computeK();

// ── Private key / verifier ───────────────────────────────────────────────────

/**
 * x = SHA256(s_bytes | SHA256(I + ':' + P))
 * Matches secure-remote-password: H(s, H(I:P)) where s is treated as a hex integer.
 */
function deriveX(saltHex: string, identity: string, password: string): bigint {
  const sBytes = hexToBytes(saltHex); // treat salt as big-endian hex → bytes
  const innerHash = sha256(new TextEncoder().encode(`${identity}:${password}`));
  const combined = new Uint8Array(sBytes.length + innerHash.length);
  combined.set(sBytes);
  combined.set(innerHash, sBytes.length);
  return bytesToBigInt(sha256(combined));
}

// ── Public API ───────────────────────────────────────────────────────────────

export interface SrpRegistrationMaterial {
  srpSalt: string;   // base64 random salt
  srpVerifier: string; // base64 verifier v = g^x mod N
}

export interface SrpStep1Result {
  clientPublicA: string; // base64 A = g^a mod N
  /** Keep in memory only — never log or store */
  privateSession: { public: string; secret: string }; // hex hex
}

export interface SrpStep2Result {
  clientProofM1: string; // base64 M1 = SHA256(A|B|S)
  sessionKey: Uint8Array; // S = raw premaster secret — for key derivation / testing
  verifyServerProof: (serverM2B64: string) => void;
}

export function generateSrpRegistration(
  email: string,
  masterPassword: string,
): SrpRegistrationMaterial {
  const saltBytes = getRandomBytes(32);
  const saltHex = bytesToHex(saltBytes);
  const x = deriveX(saltHex, email, masterPassword);
  const v = modPow(G, x, N);
  return {
    srpSalt: hexToBase64(saltHex),
    srpVerifier: hexToBase64(bytesToHex(bigIntToBytes(v))),
  };
}

export function srpStep1(): SrpStep1Result {
  const aBytes = getRandomBytes(32); // 256-bit random private ephemeral
  const a = bytesToBigInt(aBytes);
  const A = modPow(G, a, N);
  const aHex = bytesToHex(bigIntToBytes(A));
  return {
    clientPublicA: hexToBase64(aHex),
    privateSession: { public: aHex, secret: bytesToHex(bigIntToBytes(a)) },
  };
}

export function srpStep2(
  email: string,
  masterPassword: string,
  srpSaltB64: string,
  serverPublicBB64: string,
  privateSession: SrpStep1Result["privateSession"],
): SrpStep2Result {
  const saltHex = base64ToHex(srpSaltB64);
  const B = bytesToBigInt(hexToBytes(base64ToHex(serverPublicBB64)));
  const a = bytesToBigInt(hexToBytes(privateSession.secret));
  const A = bytesToBigInt(hexToBytes(privateSession.public));

  if (B % N === 0n) throw new Error("Invalid server public ephemeral B");

  const x = deriveX(saltHex, email, masterPassword);

  // u = SHA256(A_bytes | B_bytes)  — minimal bytes, matches Rust
  const aBytes = bigIntToBytes(A);
  const bBytes = bigIntToBytes(B);
  const uInput = new Uint8Array(aBytes.length + bBytes.length);
  uInput.set(aBytes);
  uInput.set(bBytes, aBytes.length);
  const u = bytesToBigInt(sha256(uInput));

  // S = (B - k*g^x)^(a + u*x) mod N
  const kgx = (K_CONST * modPow(G, x, N)) % N;
  const base = ((B - kgx) % N + N) % N;
  const exp = a + u * x;
  const S = modPow(base, exp, N);

  // M1 = SHA256(A_bytes | B_bytes | S_bytes) — Rust srp 0.6.x uses raw S, not H(S)
  const sBytes = bigIntToBytes(S);
  const m1Input = new Uint8Array(aBytes.length + bBytes.length + sBytes.length);
  m1Input.set(aBytes);
  m1Input.set(bBytes, aBytes.length);
  m1Input.set(sBytes, aBytes.length + bBytes.length);
  const m1Bytes = sha256(m1Input);

  return {
    clientProofM1: hexToBase64(bytesToHex(m1Bytes)),
    sessionKey: sBytes,
    verifyServerProof: (serverM2B64: string) => {
      // M2 = SHA256(A_bytes | M1 | S_bytes)
      const m2Input = new Uint8Array(aBytes.length + m1Bytes.length + sBytes.length);
      m2Input.set(aBytes);
      m2Input.set(m1Bytes, aBytes.length);
      m2Input.set(sBytes, aBytes.length + m1Bytes.length);
      const expectedM2 = sha256(m2Input);
      const serverM2 = hexToBytes(base64ToHex(serverM2B64));
      let diff = 0;
      if (serverM2.length !== expectedM2.length) diff = 1;
      for (let i = 0; i < expectedM2.length; i++) diff |= (expectedM2[i] ?? 0) ^ (serverM2[i] ?? 0);
      if (diff !== 0) throw new Error("Server proof M2 verification failed — mutual auth check");
    },
  };
}
