// @vitest-environment node
/**
 * The account-key lifecycle against an in-memory server: a legacy SRP
 * account logs in, upgrades (fresh SRP proof + OPAQUE + wrapped account key),
 * changes its password, and recovers with a kit made before all of it. Items
 * written at the start must decrypt at every step.
 */
import { describe, expect, it } from "vitest";
import { DEFAULT_KDF_PARAMS, type LoginItem, type RecoveryCompleteRequest, type RecoveryInitResponse } from "@nopass/types";

import { AccountKeyError, importAccountKeys, unlockAccount, unwrapAccountKey, wrapAccountKey } from "../account-key";
import { completeAccountRecovery } from "../account-recovery";
import { memoryAccountState } from "../account-state";
import { decryptItem, encryptItem } from "../aes-gcm";
import { computeEmailHash, deriveMasterKey, stretchMasterKey, stretchMasterKeyAllRaw } from "../kdf";
import { decryptUserPrivateKey, generateUserKeyPair } from "../org-crypto";
import { changeMasterPassword } from "../password-change";
import { IncorrectPasswordError, loginWithPassword } from "../password-login";
import { deriveRecoveryKeys, generateRecoveryCode, unwrapVaultSubkeys, wrapVaultSubkeys } from "../recovery";
import { fakeServer, HttpError } from "./support/fake-server";

const EMAIL = "alice@example.com";
const P1 = "first long passphrase";
const P2 = "second long passphrase";
const P3 = "third long passphrase";
const ITEM: LoginItem = {
  type: "login",
  name: "Bank",
  username: "alice",
  password: "hunter2",
  totp: "",
  urls: [],
  notes: "",
  customFields: [],
};

/** A pre-OPAQUE, pre-account-key account: items and private key under P1's derived keys, plus a kit. */
async function legacyAccount() {
  const server = await fakeServer(EMAIL);
  server.makeSrpAccount(EMAIL, P1);
  const master = await deriveMasterKey(P1, EMAIL, DEFAULT_KDF_PARAMS);
  const keys = await stretchMasterKey(master, EMAIL);
  const subkeys = await stretchMasterKeyAllRaw(master, EMAIL);
  const item = await encryptItem(ITEM, keys.vaultEncKey, keys.vaultMacKey);
  const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);
  server.account.protectedPrivateKey = keyPair.protectedPrivateKey;
  server.account.protectedPrivateKeyIv = keyPair.protectedPrivateKeyIv;
  const kitCode = generateRecoveryCode();
  const kit = await wrapVaultSubkeys(subkeys, (await deriveRecoveryKeys(kitCode, EMAIL)).wrapKey);
  return { server, item, kit, kitCode };
}

async function unlock(server: Awaited<ReturnType<typeof fakeServer>>, password: string, accountState = memoryAccountState()) {
  const session = await loginWithPassword(server.api, { email: EMAIL, password, accountState });
  const account = await unlockAccount(server.api, { email: EMAIL, password, session, accountState });
  return importAccountKeys(account);
}

it("legacy SRP account upgrades, changes password and recovers with an old kit; items decrypt throughout", async () => {
  const { server, item, kit, kitCode } = await legacyAccount();
  const accountState = memoryAccountState();

  // 1. First unlock upgrades in one request, with a fresh SRP proof.
  const first = await unlock(server, P1, accountState);
  expect(server.api.upgradeFinish).toHaveBeenCalledOnce();
  expect(server.account.srp).toBeUndefined();
  expect(await decryptItem(item, first.vaultEncKey, first.vaultMacKey)).toEqual(ITEM);
  expect(await accountState.get(computeEmailHash(EMAIL))).toEqual({ opaque: true, accountKey: true });
  // The private key moved to the account-key wrap and still opens.
  await decryptUserPrivateKey(server.account.protectedPrivateKey!, server.account.protectedPrivateKeyIv!, first.stretchedMasterKey);

  // 2. Password change re-wraps only.
  await expect(
    changeMasterPassword(server.api, { email: EMAIL, sessionToken: "t", currentPassword: "wrong", newPassword: P2 }),
  ).rejects.toBeInstanceOf(IncorrectPasswordError);
  await changeMasterPassword(server.api, { email: EMAIL, sessionToken: "t", currentPassword: P1, newPassword: P2 });
  const afterChange = await unlock(server, P2, accountState);
  expect(await decryptItem(item, afterChange.vaultEncKey, afterChange.vaultMacKey)).toEqual(ITEM);
  await expect(unlock(server, P1, accountState)).rejects.toMatchObject({ status: 401 });

  // 3. The kit made before the upgrade and the change still recovers.
  const recovered = await unwrapVaultSubkeys(kit, (await deriveRecoveryKeys(kitCode, EMAIL)).wrapKey);
  const init: RecoveryInitResponse = {
    recoveryToken: "r",
    recoveryBlob: kit.blob,
    recoveryBlobIv: kit.blobIv,
    protectedPrivateKey: server.account.protectedPrivateKey!,
    protectedPrivateKeyIv: server.account.protectedPrivateKeyIv!,
    items: [],
  };
  let completed: RecoveryCompleteRequest | undefined;
  await completeAccountRecovery(server.recoveryApi((req) => (completed = req)), {
    email: EMAIL,
    newPassword: P3,
    init,
    recovered,
  });
  expect(completed).toBeDefined();
  const afterRecovery = await unlock(server, P3, accountState);
  expect(await decryptItem(item, afterRecovery.vaultEncKey, afterRecovery.vaultMacKey)).toEqual(ITEM);
  await decryptUserPrivateKey(server.account.protectedPrivateKey!, server.account.protectedPrivateKeyIv!, afterRecovery.stretchedMasterKey);
}, 600_000);

describe("unlockAccount after migration", () => {
  it("refuses a login response without the wrap instead of deriving legacy keys", async () => {
    const { server } = await legacyAccount();
    const accountState = memoryAccountState();
    await unlock(server, P1, accountState);

    // The server now pretends the account was never migrated.
    server.account.wrappedAccountKey = undefined;
    server.account.wrappedAccountKeyIv = undefined;
    await expect(unlock(server, P1, accountState)).rejects.toBeInstanceOf(AccountKeyError);
    expect(server.api.setAccountKey).not.toHaveBeenCalled();
  }, 300_000);

  it("fails the unlock when the migration upload fails", async () => {
    const { server } = await legacyAccount();
    server.api.upgradeFinish = async () => {
      throw new HttpError(500);
    };
    await expect(unlock(server, P1)).rejects.toMatchObject({ status: 500 });
  }, 300_000);
});

it("binds the wrap to the account's email, so another account's blob doesn't open", async () => {
  const master = await deriveMasterKey(P1, EMAIL, DEFAULT_KDF_PARAMS);
  const legacy = await stretchMasterKeyAllRaw(master, EMAIL);
  const wrapped = await wrapAccountKey(legacy, master, EMAIL);
  await expect(unwrapAccountKey(wrapped, master, "mallory@example.com")).rejects.toBeInstanceOf(AccountKeyError);
}, 60_000);
