import { describe, expect, it } from "vitest";
import { generateSrpRegistration, srpStep1, srpStep2 } from "../srp-client";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  hexToBytes,
  bytesToHex,
  hexToBase64,
  base64ToHex,
  generateRustServerEphemeral,
  computeRustServerS,
  rustM1,
  rustM2,
} from "./support/rust-srp-server";

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

    serverM2Bytes[serverM2Bytes.length - 1]! ^= 0xff;
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
