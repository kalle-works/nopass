// @vitest-environment node
import { describe, it, expect, beforeAll } from "vitest";
import {
  computeEmailHash,
  deriveMasterKey,
  stretchMasterKey,
  srpStep1,
  srpStep2,
  generateUserKeyPair,
  generateOrgKey,
  encryptOrgKeyForMember,
  decryptOrgKey,
  decryptUserPrivateKey,
  generateSrpRegistration,
  stretchMasterKeyRaw,
  encryptBytes,
} from "../index.js";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";

const BASE = "http://127.0.0.1:3001/v1";

async function apiPost(path: string, body: unknown, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const r = await fetch(`${BASE}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST ${path} → ${r.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

async function apiGet(path: string, token: string) {
  const r = await fetch(`${BASE}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  const text = await r.text();
  if (!r.ok) throw new Error(`GET ${path} → ${r.status}: ${text}`);
  return JSON.parse(text);
}

async function registerAndLogin(email: string, password: string) {
  const kdfParams = DEFAULT_KDF_PARAMS;
  const masterKey = await deriveMasterKey(password, email, kdfParams);
  const keys = await stretchMasterKey(masterKey, email);
  const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, email);
  const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);
  const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
  encKeyBytes.fill(0);
  const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);

  await apiPost("/auth/register", {
    emailHash: computeEmailHash(email),
    srpSalt,
    srpVerifier,
    kdfParams,
    protectedSymmetricKey: protectedKey.blob,
    protectedSymmetricKeyIv: protectedKey.blobIv,
    publicKey: keyPair.publicKeyB64,
    protectedPrivateKey: keyPair.protectedPrivateKey,
    protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
  });

  const step1 = srpStep1();
  const initResp = await apiPost("/auth/srp/init", {
    emailHash: computeEmailHash(email),
    clientPublicA: step1.clientPublicA,
  });
  const step2 = srpStep2(email, password, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
  const verifyResp = await apiPost("/auth/srp/verify", {
    sessionId: initResp.sessionId,
    clientProofM1: step2.clientProofM1,
  });
  step2.verifyServerProof(verifyResp.serverProofM2);

  return { token: verifyResp.sessionToken as string, keys, keyPair };
}

const timestamp = Date.now();
const ALICE_EMAIL = `alice-org-${timestamp}@nopass.test`;
const BOB_EMAIL = `bob-org-${timestamp}@nopass.test`;
const PASSWORD = "correct-horse-battery-staple-99";

let aliceToken: string;
let aliceKeys: Awaited<ReturnType<typeof registerAndLogin>>["keys"];
let aliceKeyPair: Awaited<ReturnType<typeof registerAndLogin>>["keyPair"];
let bobToken: string;
let bobKeys: Awaited<ReturnType<typeof registerAndLogin>>["keys"];
let bobKeyPair: Awaited<ReturnType<typeof registerAndLogin>>["keyPair"];

// Requires a running API server — skip cleanly when it isn't reachable
const apiAvailable = await fetch(`${BASE}/health`)
  .then((r) => r.ok)
  .catch(() => false);

describe.skipIf(!apiAvailable)("Organization API — end-to-end", () => {
  beforeAll(async () => {
    const alice = await registerAndLogin(ALICE_EMAIL, PASSWORD);
    aliceToken = alice.token;
    aliceKeys = alice.keys;
    aliceKeyPair = alice.keyPair;

    const bob = await registerAndLogin(BOB_EMAIL, PASSWORD);
    bobToken = bob.token;
    bobKeys = bob.keys;
    bobKeyPair = bob.keyPair;
  }, 60_000);

  it("creates an org and returns owner role", async () => {
    const orgKey = await generateOrgKey();
    const encryptedOrgKey = await encryptOrgKeyForMember(orgKey, aliceKeyPair.publicKeyB64);

    const resp = await apiPost("/organizations", {
      name: "Acme Corp",
      publicKey: aliceKeyPair.publicKeyB64,
      protectedPrivateKey: aliceKeyPair.protectedPrivateKey,
      protectedPrivateKeyIv: aliceKeyPair.protectedPrivateKeyIv,
      encryptedOrgKey,
    }, aliceToken);

    expect(resp.name).toBe("Acme Corp");
    expect(resp.role).toBe("owner");
    expect(resp.memberCount).toBe(1);
    expect(resp.id).toBeTruthy();
  });

  let orgId: string;
  let orgEncryptedKey: string;

  it("lists orgs and decrypts org key end-to-end", async () => {
    const orgKey = await generateOrgKey();
    const encryptedOrgKey = await encryptOrgKeyForMember(orgKey, aliceKeyPair.publicKeyB64);

    const created = await apiPost("/organizations", {
      name: "Zero-Knowledge Team",
      publicKey: aliceKeyPair.publicKeyB64,
      protectedPrivateKey: aliceKeyPair.protectedPrivateKey,
      protectedPrivateKeyIv: aliceKeyPair.protectedPrivateKeyIv,
      encryptedOrgKey,
    }, aliceToken);

    orgId = created.id as string;

    const orgs = await apiGet("/organizations", aliceToken);
    const found = (orgs as Array<{ id: string; name: string }>).find((o) => o.id === orgId);
    expect(found?.name).toBe("Zero-Knowledge Team");

    // Fetch details + decrypt org key
    const details = await apiGet(`/organizations/${orgId}`, aliceToken);
    orgEncryptedKey = details.encryptedOrgKey as string;

    const privateKey = await decryptUserPrivateKey(
      aliceKeyPair.protectedPrivateKey,
      aliceKeyPair.protectedPrivateKeyIv,
      aliceKeys.stretchedMasterKey,
    );
    const decrypted = await decryptOrgKey(details.encryptedOrgKey, privateKey);
    expect(decrypted.type).toBe("secret");
    expect(decrypted.algorithm.name).toBe("AES-GCM");
  });

  it("looks up public key by email hash", async () => {
    // Need Alice to have a public key registered — already done via org creation above
    const emailHash = computeEmailHash(ALICE_EMAIL);
    const resp = await apiGet(`/organizations/public-key/${emailHash}`, aliceToken);
    expect(resp.publicKey).toBeTruthy();
    expect(resp.userId).toBeTruthy();
  });

  it("invites Bob and Bob can decrypt the org key", async () => {
    if (!orgId) return; // depends on previous test

    // Alice looks up Bob's public key
    const bobEmailHash = computeEmailHash(BOB_EMAIL);

    // Bob needs to have a public key — he needs to have created an org or registered one.
    // Let's create an org for Bob first to register his public key
    const bobOrgKey = await generateOrgKey();
    const bobEncOrgKey = await encryptOrgKeyForMember(bobOrgKey, bobKeyPair.publicKeyB64);
    await apiPost("/organizations", {
      name: "Bob's Org",
      publicKey: bobKeyPair.publicKeyB64,
      protectedPrivateKey: bobKeyPair.protectedPrivateKey,
      protectedPrivateKeyIv: bobKeyPair.protectedPrivateKeyIv,
      encryptedOrgKey: bobEncOrgKey,
    }, bobToken);

    // Now Alice fetches Bob's public key
    const pkResp = await apiGet(`/organizations/public-key/${bobEmailHash}`, aliceToken);
    expect(pkResp.publicKey).toBeTruthy();

    // Alice re-encrypts org key for Bob
    const alicePrivateKey = await decryptUserPrivateKey(
      aliceKeyPair.protectedPrivateKey,
      aliceKeyPair.protectedPrivateKeyIv,
      aliceKeys.stretchedMasterKey,
    );
    const orgKey = await decryptOrgKey(orgEncryptedKey, alicePrivateKey);
    const encKeyForBob = await encryptOrgKeyForMember(orgKey, pkResp.publicKey as string);

    // Invite Bob
    await apiPost(`/organizations/${orgId}/members`, {
      emailHash: bobEmailHash,
      role: "member",
      encryptedOrgKey: encKeyForBob,
    }, aliceToken);

    // Bob accepts
    await apiPost(`/organizations/${orgId}/accept`, {}, bobToken);

    // Bob fetches org details and decrypts the org key
    const details = await apiGet(`/organizations/${orgId}`, bobToken);
    expect(details.members.length).toBe(2);

    const bobPrivateKey = await decryptUserPrivateKey(
      bobKeyPair.protectedPrivateKey,
      bobKeyPair.protectedPrivateKeyIv,
      bobKeys.stretchedMasterKey,
    );
    const bobDecryptedKey = await decryptOrgKey(details.encryptedOrgKey, bobPrivateKey);
    expect(bobDecryptedKey.type).toBe("secret");
    expect(bobDecryptedKey.algorithm.name).toBe("AES-GCM");
  }, 30_000);

  it("non-member cannot see org details", async () => {
    // Alice tries to access Bob's standalone org (Bob's Org) — she was never invited
    // Bob created "Bob's Org" inside the invite test; fetch Bob's org list to get its ID
    const bobOrgs = await apiGet("/organizations", bobToken) as Array<{ id: string; name: string }>;
    const bobsOrg = bobOrgs.find((o) => o.name === "Bob's Org");
    if (!bobsOrg) return; // only runs if invite test ran first

    await expect(apiGet(`/organizations/${bobsOrg.id}`, aliceToken)).rejects.toThrow("404");
  });
});
