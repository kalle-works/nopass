import { describe, it, expect } from "vitest";
import {
  bytesToB64u,
  b64uToBytes,
  cborEncode,
  generateCredential,
  buildAuthenticatorData,
  buildAttestationObject,
  rawSigToDer,
  signAssertion,
  rpIdMatchesOrigin,
  FLAG_UP,
  FLAG_UV,
  SYNCED_FLAGS,
} from "../webauthn";

const te = new TextEncoder();

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255, 62, 63]);
    expect([...b64uToBytes(bytesToB64u(bytes))]).toEqual([...bytes]);
  });

  it("emits no padding or url-unsafe characters", () => {
    const bytes = new Uint8Array(33).fill(0xff);
    const s = bytesToB64u(bytes);
    expect(s).not.toMatch(/[+/=]/);
  });
});

describe("cborEncode", () => {
  it("encodes small unsigned ints inline", () => {
    expect([...cborEncode(2)]).toEqual([0x02]);
    expect([...cborEncode(23)]).toEqual([0x17]);
    expect([...cborEncode(24)]).toEqual([0x18, 24]);
  });

  it("encodes negative ints", () => {
    expect([...cborEncode(-7)]).toEqual([0x26]); // major 1, value 6
  });

  it("encodes text and byte strings with length prefixes", () => {
    expect([...cborEncode("none")]).toEqual([0x64, 0x6e, 0x6f, 0x6e, 0x65]);
    expect([...cborEncode(new Uint8Array([1, 2, 3]))]).toEqual([0x43, 1, 2, 3]);
  });

  it("encodes maps in insertion order", () => {
    const m = new Map<number | string, number>([[1, 2], [3, -7]]);
    expect([...cborEncode(m)]).toEqual([0xa2, 0x01, 0x02, 0x03, 0x26]);
  });
});

describe("generateCredential", () => {
  it("produces a 32-byte credential id and a COSE EC2 key", async () => {
    const cred = await generateCredential();
    expect(cred.credentialId.length).toBe(32);
    // COSE map header: 5 entries (kty, alg, crv, x, y)
    expect(cred.cosePublicKey[0]).toBe(0xa5);
    // pkcs8 P-256 keys are ~138 bytes
    expect(cred.privateKeyPkcs8.length).toBeGreaterThan(100);
  });
});

describe("buildAuthenticatorData", () => {
  it("lays out rpIdHash, flags, and counter for assertions", async () => {
    const authData = await buildAuthenticatorData("example.com", FLAG_UP | FLAG_UV, 42);
    expect(authData.length).toBe(37);

    const expectedHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", te.encode("example.com")),
    );
    expect([...authData.slice(0, 32)]).toEqual([...expectedHash]);
    expect(authData[32]).toBe(FLAG_UP | FLAG_UV);
    expect(new DataView(authData.buffer).getUint32(33, false)).toBe(42);
  });

  it("appends attested credential data with the AT flag for registration", async () => {
    const cred = await generateCredential();
    const authData = await buildAuthenticatorData("example.com", FLAG_UP | SYNCED_FLAGS, 0, {
      credentialId: cred.credentialId,
      cosePublicKey: cred.cosePublicKey,
    });

    expect(authData[32]! & 0x40).toBe(0x40); // AT flag
    // 37 header + 16 aaguid + 2 len + 32 credId + cose
    expect(authData.length).toBe(37 + 16 + 2 + 32 + cred.cosePublicKey.length);
    const credIdLen = new DataView(authData.buffer).getUint16(37 + 16, false);
    expect(credIdLen).toBe(32);
    expect([...authData.slice(55, 87)]).toEqual([...cred.credentialId]);
  });
});

describe("buildAttestationObject", () => {
  it("wraps authData in a none-format CBOR envelope", async () => {
    const authData = await buildAuthenticatorData("example.com", FLAG_UP, 0);
    const att = buildAttestationObject(authData);
    // map(3) "fmt" "none" "attStmt" {} "authData" bytes
    expect(att[0]).toBe(0xa3);
    const text = new TextDecoder("latin1").decode(att);
    expect(text).toContain("fmt");
    expect(text).toContain("none");
    expect(text).toContain("authData");
  });
});

describe("rawSigToDer", () => {
  it("strips leading zeros and pads high-bit integers", () => {
    const r = new Uint8Array(32).fill(0);
    r[31] = 1; // r = 1
    const s = new Uint8Array(32).fill(0x80); // high bit set
    const der = rawSigToDer(new Uint8Array([...r, ...s]));
    // SEQUENCE, len, INT 1 byte (1), INT 33 bytes (0x00 + 32)
    expect(der[0]).toBe(0x30);
    expect(der[2]).toBe(0x02);
    expect(der[3]).toBe(1);
    expect(der[4]).toBe(1);
    expect(der[5]).toBe(0x02);
    expect(der[6]).toBe(33);
    expect(der[7]).toBe(0x00);
  });
});

describe("signAssertion", () => {
  it("produces a DER signature WebCrypto can verify against authData||hash", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

    const authData = await buildAuthenticatorData("example.com", FLAG_UP, 7);
    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", te.encode('{"type":"webauthn.get"}')),
    );

    const der = await signAssertion(pkcs8, authData, clientDataHash);

    // Convert DER back to raw r||s so WebCrypto can verify it
    const rLen = der[3]!;
    const rRaw = der.slice(4, 4 + rLen);
    const sLen = der[4 + rLen + 1]!;
    const sRaw = der.slice(4 + rLen + 2, 4 + rLen + 2 + sLen);
    const pad = (b: Uint8Array) => {
      const trimmed = b[0] === 0 ? b.slice(1) : b;
      const out = new Uint8Array(32);
      out.set(trimmed, 32 - trimmed.length);
      return out;
    };
    const rawSig = new Uint8Array([...pad(rRaw), ...pad(sRaw)]);

    const signedData = new Uint8Array([...authData, ...clientDataHash]);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.publicKey,
      rawSig,
      signedData,
    );
    expect(ok).toBe(true);
  });
});

describe("rpIdMatchesOrigin", () => {
  it("accepts the exact host and registrable suffixes", () => {
    expect(rpIdMatchesOrigin("example.com", "https://example.com")).toBe(true);
    expect(rpIdMatchesOrigin("example.com", "https://login.example.com")).toBe(true);
  });

  it("rejects cross-site and malformed rp ids", () => {
    expect(rpIdMatchesOrigin("bank.com", "https://evil.com")).toBe(false);
    expect(rpIdMatchesOrigin("le.com", "https://example.com")).toBe(false); // suffix but not label boundary
    expect(rpIdMatchesOrigin(".example.com", "https://example.com")).toBe(false);
    expect(rpIdMatchesOrigin("", "https://example.com")).toBe(false);
    expect(rpIdMatchesOrigin("example.com", "not-a-url")).toBe(false);
  });
});
