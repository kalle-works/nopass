import { describe, expect, it } from "vitest";
import { generateSrpRegistration, srpStep1, srpStep2 } from "../srp-client";
import { sha256 } from "@noble/hashes/sha2.js";

// G_2048 group parameters — must match srp-client.ts exactly
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
const N_BYTES = 256;

// ── Shared helpers (mirror srp-client.ts) ─────────────────────────────────────

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
function bigIntToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(1);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return hexToBytes(hex);
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

// ── Rust srp 0.6.x server helpers ────────────────────────────────────────────

/**
 * k = SHA256(N_bytes | PAD(g_bytes, N_BYTES)) — Rust srp 0.6.x formula.
 * Must match computeK() in srp-client.ts.
 */
function computeKRust(): bigint {
  const nBytes = hexToBytes(N_HEX);
  const gBytes = bigIntToBytes(G);
  const padded = new Uint8Array(N_BYTES); // zero-padded
  padded.set(gBytes, N_BYTES - gBytes.length); // right-align
  const input = new Uint8Array(N_BYTES + N_BYTES);
  input.set(nBytes, 0);
  input.set(padded, N_BYTES);
  return BigInt("0x" + bytesToHex(sha256(input)));
}

const K_RUST = computeKRust();

/**
 * Generate a Rust-compatible server ephemeral:
 *   B = k_Rust * v + g^b mod N
 *
 * The `secure-remote-password` npm server uses k_JS (g not padded), so its B
 * is incompatible with our client.  We generate B here using the correct k so
 * client and server arrive at the same S.
 */
function generateRustServerEphemeral(verifierHex: string): { public: string; secret: string } {
  const bRaw = new Uint8Array(32);
  crypto.getRandomValues(bRaw);
  const b = BigInt("0x" + bytesToHex(bRaw));
  const v = BigInt("0x" + verifierHex);
  const B = (K_RUST * v + modPow(G, b, N)) % N;
  return {
    public: bytesToHex(bigIntToBytes(B)),
    secret: bytesToHex(bigIntToBytes(b)),
  };
}

/**
 * Compute shared premaster secret S from the server side using Rust srp 0.6.x:
 *   u = SHA256(A_bytes | B_bytes)   — minimal (no padding)
 *   S = (A * v^u)^b mod N
 *
 * The Rust crate uses raw S (not H(S)) directly in M1 and M2.
 */
function computeRustServerS(
  clientPublicAHex: string,
  serverPublicBHex: string,
  serverPrivateBHex: string,
  verifierHex: string,
): Uint8Array {
  const A = BigInt("0x" + clientPublicAHex);
  const B = BigInt("0x" + serverPublicBHex);
  const b = BigInt("0x" + serverPrivateBHex);
  const v = BigInt("0x" + verifierHex);

  const aBytes = bigIntToBytes(A);
  const bBytes = bigIntToBytes(B);
  const uInput = new Uint8Array(aBytes.length + bBytes.length);
  uInput.set(aBytes);
  uInput.set(bBytes, aBytes.length);
  const u = BigInt("0x" + bytesToHex(sha256(uInput)));

  const vu = modPow(v, u, N);
  const base = (A * vu) % N;
  const S = modPow(base, b, N);
  return bigIntToBytes(S);
}

/** Rust srp 0.6.x: M1 = H(A | B | S) */
function rustM1(aHex: string, bHex: string, sBytes: Uint8Array): Uint8Array {
  const a = hexToBytes(aHex);
  const b = hexToBytes(bHex);
  return sha256(new Uint8Array([...a, ...b, ...sBytes]));
}

/** Rust srp 0.6.x: M2 = H(A | M1 | S) */
function rustM2(aHex: string, m1Bytes: Uint8Array, sBytes: Uint8Array): Uint8Array {
  const a = hexToBytes(aHex);
  return sha256(new Uint8Array([...a, ...m1Bytes, ...sBytes]));
}

// ── tests ────────────────────────────────────────────────────────────────────

describe("generateSrpRegistration", () => {
  it("produces a non-empty salt and verifier (base64 encoded)", () => {
    const { srpSalt, srpVerifier } = generateSrpRegistration(
      "alice@example.com",
      "correct horse battery staple",
    );
    expect(srpSalt.length).toBeGreaterThan(0);
    expect(srpVerifier.length).toBeGreaterThan(0);
    expect(() => atob(srpSalt)).not.toThrow();
    expect(() => atob(srpVerifier)).not.toThrow();
  });

  it("different calls produce different salts", () => {
    const r1 = generateSrpRegistration("alice@example.com", "password");
    const r2 = generateSrpRegistration("alice@example.com", "password");
    expect(r1.srpSalt).not.toBe(r2.srpSalt);
    expect(r1.srpVerifier).not.toBe(r2.srpVerifier);
  });

  it("different emails produce different verifiers for same password", () => {
    const r1 = generateSrpRegistration("alice@example.com", "samepassword");
    const r2 = generateSrpRegistration("bob@example.com", "samepassword");
    expect(r1.srpVerifier).not.toBe(r2.srpVerifier);
  });
});

describe("srpStep1", () => {
  it("returns base64 clientPublicA and a privateSession", () => {
    const step1 = srpStep1();
    expect(step1.clientPublicA).toBeTruthy();
    expect(() => atob(step1.clientPublicA)).not.toThrow();
    expect(step1.privateSession).toBeTruthy();
  });
});

describe("srpStep2 — M1 = H(A|B|K) compatible with Rust srp 0.6.x", () => {
  it("client and server derive the same session key K", () => {
    const email = "alice@example.com";
    const password = "correct horse battery staple";
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);

    const step1 = srpStep1();
    const verifierHex = base64ToHex(srpVerifier);
    const serverEphemeral = generateRustServerEphemeral(verifierHex);
    const serverPublicBB64 = hexToBase64(serverEphemeral.public);

    const step2 = srpStep2(email, password, srpSalt, serverPublicBB64, step1.privateSession);

    const clientPublicAHex = step1.privateSession.public;
    const sServer = computeRustServerS(
      clientPublicAHex,
      serverEphemeral.public,
      serverEphemeral.secret,
      verifierHex,
    );

    expect(bytesToHex(step2.sessionKey)).toBe(bytesToHex(sServer));
  });

  it("produces M1 matching the Rust srp formula", () => {
    const email = "alice@example.com";
    const password = "correct horse battery staple";
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);

    const step1 = srpStep1();
    const verifierHex = base64ToHex(srpVerifier);
    // Use Rust-compatible B so client and server share the same S
    const serverEphemeral = generateRustServerEphemeral(verifierHex);
    const serverPublicBB64 = hexToBase64(serverEphemeral.public);

    const step2 = srpStep2(email, password, srpSalt, serverPublicBB64, step1.privateSession);

    const clientPublicAHex = step1.privateSession.public;
    const kBytes = computeRustServerS(
      clientPublicAHex,
      serverEphemeral.public,
      serverEphemeral.secret,
      verifierHex,
    );

    const expectedM1 = rustM1(clientPublicAHex, serverEphemeral.public, kBytes);
    expect(step2.clientProofM1).toBe(hexToBase64(bytesToHex(expectedM1)));
  });

  it("verifyServerProof passes for correct M2 = H(A|M1|K)", () => {
    const email = "alice@example.com";
    const password = "correct horse battery staple";
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);

    const step1 = srpStep1();
    const verifierHex = base64ToHex(srpVerifier);
    const serverEphemeral = generateRustServerEphemeral(verifierHex);
    const serverPublicBB64 = hexToBase64(serverEphemeral.public);

    const step2 = srpStep2(email, password, srpSalt, serverPublicBB64, step1.privateSession);

    const clientPublicAHex = step1.privateSession.public;
    const kBytes = computeRustServerS(
      clientPublicAHex,
      serverEphemeral.public,
      serverEphemeral.secret,
      verifierHex,
    );

    const m1Bytes = hexToBytes(base64ToHex(step2.clientProofM1));
    const serverM2Bytes = rustM2(clientPublicAHex, m1Bytes, kBytes);
    const serverM2B64 = hexToBase64(bytesToHex(serverM2Bytes));

    expect(() => step2.verifyServerProof(serverM2B64)).not.toThrow();
  });

  it("verifyServerProof throws when M2 is tampered", () => {
    const email = "alice@example.com";
    const password = "correct-password";
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);

    const step1 = srpStep1();
    const verifierHex = base64ToHex(srpVerifier);
    const serverEphemeral = generateRustServerEphemeral(verifierHex);
    const serverPublicBB64 = hexToBase64(serverEphemeral.public);

    const step2 = srpStep2(email, password, srpSalt, serverPublicBB64, step1.privateSession);

    const clientPublicAHex = step1.privateSession.public;
    const kBytes = computeRustServerS(
      clientPublicAHex,
      serverEphemeral.public,
      serverEphemeral.secret,
      verifierHex,
    );
    const m1Bytes = hexToBytes(base64ToHex(step2.clientProofM1));
    const serverM2Bytes = rustM2(clientPublicAHex, m1Bytes, kBytes);

    serverM2Bytes[serverM2Bytes.length - 1] ^= 0xff;
    const tamperedM2B64 = hexToBase64(bytesToHex(serverM2Bytes));

    expect(() => step2.verifyServerProof(tamperedM2B64)).toThrow();
  });

  it("M1 differs when wrong password is used", () => {
    const email = "alice@example.com";
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, "correct-password");

    const step1 = srpStep1();
    const verifierHex = base64ToHex(srpVerifier);
    const serverEphemeral = generateRustServerEphemeral(verifierHex);
    const serverPublicBB64 = hexToBase64(serverEphemeral.public);

    const step2Wrong = srpStep2(email, "wrong-password", srpSalt, serverPublicBB64, step1.privateSession);
    const step2Correct = srpStep2(email, "correct-password", srpSalt, serverPublicBB64, step1.privateSession);

    expect(step2Wrong.clientProofM1).not.toBe(step2Correct.clientProofM1);
  });
});
