// @vitest-environment node
/**
 * The account-key lifecycle against an in-memory server: a legacy account
 * unlocks and migrates, changes its password, and recovers with a kit made
 * before both. Items written at the start must decrypt at every step.
 */
import * as opaque from "@serenity-kit/opaque";
import { expect, it, vi } from "vitest";
import {
  DEFAULT_KDF_PARAMS,
  type KdfParams,
  type LoginItem,
  type LoginResponse,
  type RecoveryCompleteRequest,
  type RecoveryInitResponse,
} from "@nopass/types";

import { AccountKeyError, importAccountKeys, unlockAccount, type AccountKeyApi } from "../account-key";
import { completeAccountRecovery } from "../account-recovery";
import { decryptItem, encryptItem } from "../aes-gcm";
import { computeEmailHash, deriveMasterKey, stretchMasterKey, stretchMasterKeyAllRaw } from "../kdf";
import { decryptUserPrivateKey, generateUserKeyPair } from "../org-crypto";
import { changeMasterPassword, IncorrectPasswordError, type PasswordChangeApi } from "../password-change";
import { createOpaqueRegistration } from "../password-login";
import { deriveRecoveryKeys, generateRecoveryCode, unwrapVaultSubkeys, wrapVaultSubkeys } from "../recovery";

const EMAIL = "alice@example.com";
const USER_ID = "7d5c2f9e-3a41-4c3e-9d7b-5f2a1e8c6b40";
const P1 = "first long passphrase";
const P2 = "second long passphrase";
const P3 = "third long passphrase";
const KSF: KdfParams = { type: "argon2id", memoryKib: 1024, iterations: 1, parallelism: 1 };
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

/** The server's view of one account. */
interface Account {
  record: string;
  wrappedAccountKey?: string;
  wrappedAccountKeyIv?: string;
  protectedPrivateKey: string;
  protectedPrivateKeyIv: string;
}

const userIdentifier = computeEmailHash(EMAIL);

function session(a: Account): LoginResponse {
  return {
    sessionToken: "t",
    userId: USER_ID,
    defaultVaultId: "v",
    protectedSymmetricKey: "",
    protectedSymmetricKeyIv: "",
    protectedPrivateKey: a.protectedPrivateKey,
    protectedPrivateKeyIv: a.protectedPrivateKeyIv,
    wrappedAccountKey: a.wrappedAccountKey ?? null,
    wrappedAccountKeyIv: a.wrappedAccountKeyIv ?? null,
  };
}

async function decryptsItem(keys: Awaited<ReturnType<typeof importAccountKeys>>, blob: Awaited<ReturnType<typeof encryptItem>>) {
  return decryptItem(blob, keys.vaultEncKey, keys.vaultMacKey);
}

it("legacy account migrates, changes password and recovers with an old kit; items decrypt throughout", async () => {
  await opaque.ready;
  const serverSetup = opaque.server.createSetup();
  const register = (password: string) =>
    createOpaqueRegistration(password, KSF, async (registrationRequest) =>
      opaque.server.createRegistrationResponse({ serverSetup, userIdentifier, registrationRequest }),
    );

  // ── A pre-account-key account: items and private key under P1's derived keys, plus a kit.
  const legacyMaster = await deriveMasterKey(P1, EMAIL, DEFAULT_KDF_PARAMS);
  const legacyKeys = await stretchMasterKey(legacyMaster, EMAIL);
  const legacySubkeys = await stretchMasterKeyAllRaw(legacyMaster, EMAIL);
  const item = await encryptItem(ITEM, legacyKeys.vaultEncKey, legacyKeys.vaultMacKey);
  const keyPair = await generateUserKeyPair(legacyKeys.stretchedMasterKey);
  const kitCode = generateRecoveryCode();
  const kitKeys = await deriveRecoveryKeys(kitCode, EMAIL);
  const kit = await wrapVaultSubkeys(legacySubkeys, kitKeys.wrapKey);
  const account: Account = {
    record: await register(P1),
    protectedPrivateKey: keyPair.protectedPrivateKey,
    protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
  };

  const keyApi: AccountKeyApi = {
    setAccountKey: vi.fn(async (req) => {
      account.wrappedAccountKey = req.wrappedAccountKey;
      account.wrappedAccountKeyIv = req.wrappedAccountKeyIv;
      account.protectedPrivateKey = req.protectedPrivateKey!;
      account.protectedPrivateKeyIv = req.protectedPrivateKeyIv!;
    }),
  };

  // ── 1. First unlock migrates: the uploaded wrap opens to the same keys.
  const first = await unlockAccount(keyApi, { email: EMAIL, password: P1, session: session(account) });
  expect(keyApi.setAccountKey).toHaveBeenCalledOnce();
  expect(await decryptsItem(await importAccountKeys(first), item)).toEqual(ITEM);
  const again = await unlockAccount(keyApi, { email: EMAIL, password: P1, session: session(account) });
  expect(keyApi.setAccountKey).toHaveBeenCalledOnce();
  const againKeys = await importAccountKeys(again);
  expect(await decryptsItem(againKeys, item)).toEqual(ITEM);
  // The private key moved to the account-key-derived wrap and still opens.
  await decryptUserPrivateKey(account.protectedPrivateKey, account.protectedPrivateKeyIv, againKeys.stretchedMasterKey);

  // ── 2. Password change re-wraps only.
  let loginState = "";
  let pendingRecord = "";
  const changeApi: PasswordChangeApi = {
    passwordChangeStart: async (req) => {
      const login = opaque.server.startLogin({
        serverSetup,
        registrationRecord: account.record,
        startLoginRequest: req.startLoginRequest,
        userIdentifier,
      });
      loginState = login.serverLoginState;
      return {
        changeId: "c",
        loginResponse: login.loginResponse,
        kdfParams: KSF,
        registrationResponse: opaque.server.createRegistrationResponse({
          serverSetup,
          userIdentifier,
          registrationRequest: req.registrationRequest,
        }).registrationResponse,
        wrappedAccountKey: account.wrappedAccountKey!,
        wrappedAccountKeyIv: account.wrappedAccountKeyIv!,
      };
    },
    passwordChangeFinish: async (req) => {
      opaque.server.finishLogin({ serverLoginState: loginState, finishLoginRequest: req.finishLoginRequest });
      pendingRecord = req.registrationRecord;
      account.record = req.registrationRecord;
      account.wrappedAccountKey = req.wrappedAccountKey;
      account.wrappedAccountKeyIv = req.wrappedAccountKeyIv;
    },
  };
  await expect(
    changeMasterPassword(changeApi, { email: EMAIL, userId: USER_ID, sessionToken: "t", currentPassword: "wrong", newPassword: P2 }),
  ).rejects.toBeInstanceOf(IncorrectPasswordError);
  await changeMasterPassword(changeApi, { email: EMAIL, userId: USER_ID, sessionToken: "t", currentPassword: P1, newPassword: P2 });
  expect(pendingRecord).not.toBe("");

  const afterChange = await importAccountKeys(await unlockAccount(keyApi, { email: EMAIL, password: P2, session: session(account) }));
  expect(await decryptsItem(afterChange, item)).toEqual(ITEM);
  // The old password neither logs in nor opens the wrap.
  const oldLogin = opaque.client.startLogin({ password: P1 });
  const oldResponse = opaque.server.startLogin({
    serverSetup,
    registrationRecord: account.record,
    startLoginRequest: oldLogin.startLoginRequest,
    userIdentifier,
  });
  expect(
    opaque.client.finishLogin({
      clientLoginState: oldLogin.clientLoginState,
      loginResponse: oldResponse.loginResponse,
      password: P1,
      keyStretching: { "argon2id-custom": { iterations: 1, memory: 1024, parallelism: 1 } },
    }),
  ).toBeUndefined();
  await expect(unlockAccount(keyApi, { email: EMAIL, password: P1, session: session(account) })).rejects.toBeInstanceOf(
    AccountKeyError,
  );

  // ── 3. The kit made before migration and before the change still recovers.
  const recovered = await unwrapVaultSubkeys(kit, (await deriveRecoveryKeys(kitCode, EMAIL)).wrapKey);
  const init: RecoveryInitResponse = {
    recoveryToken: "r",
    userId: USER_ID,
    recoveryBlob: kit.blob,
    recoveryBlobIv: kit.blobIv,
    protectedPrivateKey: account.protectedPrivateKey,
    protectedPrivateKeyIv: account.protectedPrivateKeyIv,
    items: [],
  };
  let completed: RecoveryCompleteRequest | undefined;
  await completeAccountRecovery(
    {
      opaqueStart: async (req) =>
        opaque.server.createRegistrationResponse({ serverSetup, userIdentifier, registrationRequest: req.registrationRequest }),
      complete: async (req) => {
        completed = req;
      },
    },
    { email: EMAIL, newPassword: P3, init, recovered },
  );
  account.wrappedAccountKey = completed!.wrappedAccountKey;
  account.wrappedAccountKeyIv = completed!.wrappedAccountKeyIv;
  account.protectedPrivateKey = completed!.protectedPrivateKey!;
  account.protectedPrivateKeyIv = completed!.protectedPrivateKeyIv!;

  const afterRecovery = await importAccountKeys(await unlockAccount(keyApi, { email: EMAIL, password: P3, session: session(account) }));
  expect(await decryptsItem(afterRecovery, item)).toEqual(ITEM);
  await decryptUserPrivateKey(account.protectedPrivateKey, account.protectedPrivateKeyIv, afterRecovery.stretchedMasterKey);
}, 300_000);

it("binds the wrap to the user id, so another account's blob doesn't open", async () => {
  const master = await deriveMasterKey(P1, EMAIL, DEFAULT_KDF_PARAMS);
  const { wrapAccountKey, unwrapAccountKey } = await import("../account-key");
  const legacy = await stretchMasterKeyAllRaw(master, EMAIL);
  const wrapped = await wrapAccountKey(legacy, master, EMAIL, USER_ID);
  await expect(unwrapAccountKey(wrapped, master, EMAIL, "00000000-0000-0000-0000-000000000000")).rejects.toBeInstanceOf(
    AccountKeyError,
  );
}, 60_000);
