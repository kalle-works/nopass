/**
 * Software WebAuthn authenticator primitives.
 *
 * nopwd acts as a platform authenticator: it generates ES256 (P-256)
 * credentials, stores them in the vault, and signs assertions. Everything
 * here is pure data construction per the WebAuthn L2 / CTAP2 specs:
 * authenticator data layout, COSE_Key encoding, a minimal CBOR writer for
 * the "none"-format attestation object, and raw→DER ECDSA conversion
 * (WebCrypto emits r||s, WebAuthn expects ASN.1 DER).
 */

const te = new TextEncoder();

// ─── base64url ────────────────────────────────────────────────────────────────

export function bytesToB64u(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uToBytes(b64u: string): Uint8Array<ArrayBuffer> {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const s = atob(padded);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ─── Minimal CBOR writer ──────────────────────────────────────────────────────
// Only what an attestation object needs: unsigned ints, negative ints, byte
// strings, text strings, and definite-length maps with those as keys/values.

type CborValue = number | string | Uint8Array | CborMap;
type CborMap = Map<number | string, CborValue>;

function cborHead(major: number, length: number): number[] {
  if (length < 24) return [(major << 5) | length];
  if (length < 0x100) return [(major << 5) | 24, length];
  if (length < 0x10000) return [(major << 5) | 25, length >> 8, length & 0xff];
  return [
    (major << 5) | 26,
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  ];
}

export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encodeInto(value, out);
  return new Uint8Array(out);
}

function encodeInto(value: CborValue, out: number[]): void {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("CBOR: only integers supported");
    if (value >= 0) out.push(...cborHead(0, value));
    else out.push(...cborHead(1, -value - 1));
  } else if (typeof value === "string") {
    const bytes = te.encode(value);
    out.push(...cborHead(3, bytes.length), ...bytes);
  } else if (value instanceof Uint8Array) {
    out.push(...cborHead(2, value.length), ...value);
  } else if (value instanceof Map) {
    // CTAP2 canonical order: shorter keys first, then bytewise — callers pass
    // entries already in canonical order; we encode in insertion order
    out.push(...cborHead(5, value.size));
    for (const [k, v] of value) {
      encodeInto(k, out);
      encodeInto(v, out);
    }
  } else {
    throw new Error("CBOR: unsupported value");
  }
}

// ─── Credential creation ──────────────────────────────────────────────────────

export interface CreatedCredential {
  credentialId: Uint8Array<ArrayBuffer>;
  privateKeyPkcs8: Uint8Array<ArrayBuffer>;
  /** COSE_Key (EC2 / ES256) encoding of the public key */
  cosePublicKey: Uint8Array;
  /** SubjectPublicKeyInfo DER — what AuthenticatorAttestationResponse.getPublicKey() returns */
  publicKeySpki: Uint8Array<ArrayBuffer>;
}

/** Generate a fresh ES256 credential. */
export async function generateCredential(): Promise<CreatedCredential> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  // raw = 0x04 || X (32) || Y (32)
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);

  const cose: CborMap = new Map<number | string, CborValue>([
    [1, 2], // kty: EC2
    [3, -7], // alg: ES256
    [-1, 1], // crv: P-256
    [-2, x],
    [-3, y],
  ]);

  const credentialId = new Uint8Array(32);
  crypto.getRandomValues(credentialId);

  return {
    credentialId,
    privateKeyPkcs8: pkcs8,
    cosePublicKey: cborEncode(cose),
    publicKeySpki: spki,
  };
}

// ─── Authenticator data ───────────────────────────────────────────────────────

export const FLAG_UP = 0x01; // user present
export const FLAG_UV = 0x04; // user verified
export const FLAG_AT = 0x40; // attested credential data included
export const FLAG_BE = 0x08; // backup eligible
export const FLAG_BS = 0x10; // backed up

/** nopwd credentials are synced (vault-backed), so BE/BS are always set. */
export const SYNCED_FLAGS = FLAG_BE | FLAG_BS;

// Fixed AAGUID for the nopwd software authenticator (zero is also valid for
// "none" attestation, but a stable id helps RP dashboards label the entry)
const AAGUID = new Uint8Array([
  0x6e, 0x6f, 0x70, 0x77, 0x64, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);

export async function buildAuthenticatorData(
  rpId: string,
  flags: number,
  signCount: number,
  attested?: { credentialId: Uint8Array; cosePublicKey: Uint8Array },
): Promise<Uint8Array<ArrayBuffer>> {
  const rpIdHash = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(rpId)));

  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, signCount, false);

  const parts: Uint8Array[] = [rpIdHash, new Uint8Array([flags | (attested ? FLAG_AT : 0)]), counter];

  if (attested) {
    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, attested.credentialId.length, false);
    parts.push(AAGUID, credIdLen, attested.credentialId, attested.cosePublicKey);
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** "none"-format attestation object: { fmt: "none", attStmt: {}, authData } */
export function buildAttestationObject(authData: Uint8Array): Uint8Array {
  const obj: CborMap = new Map<number | string, CborValue>([
    ["fmt", "none"],
    ["attStmt", new Map()],
    ["authData", authData],
  ]);
  return cborEncode(obj);
}

// ─── Assertion signing ────────────────────────────────────────────────────────

/** Convert WebCrypto's raw r||s ECDSA signature to ASN.1 DER. */
export function rawSigToDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const encodeInt = (bytes: Uint8Array): number[] => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = Array.from(bytes.slice(i));
    if (v[0]! & 0x80) v = [0, ...v];
    return [0x02, v.length, ...v];
  };
  const r = encodeInt(raw.slice(0, half));
  const s = encodeInt(raw.slice(half));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

/** Sign authenticatorData || clientDataHash with the credential's key. */
export async function signAssertion(
  privateKeyPkcs8: Uint8Array<ArrayBuffer>,
  authData: Uint8Array,
  clientDataHash: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    privateKeyPkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );

  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData, 0);
  signedData.set(clientDataHash, authData.length);

  const rawSig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, signedData),
  );
  return rawSigToDer(rawSig);
}

// ─── RP ID validation ─────────────────────────────────────────────────────────

/**
 * A page may only use an rp.id that is a registrable suffix of its origin's
 * host (per WebAuthn §5.1.3). This rejects cross-site credential creation —
 * evil.com cannot register or request a credential for bank.com.
 * (Public-suffix checks are the browser's job; this guards the extension.)
 */
export function rpIdMatchesOrigin(rpId: string, origin: string): boolean {
  let host: string;
  try {
    host = new URL(origin).hostname;
  } catch {
    return false;
  }
  if (!rpId || rpId.startsWith(".") || rpId.endsWith(".")) return false;
  return host === rpId || host.endsWith(`.${rpId}`);
}
