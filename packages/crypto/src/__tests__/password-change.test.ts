// @vitest-environment node
import * as opaque from "@serenity-kit/opaque";
import { describe, expect, it, vi } from "vitest";
import { DEFAULT_KDF_PARAMS, type KdfParams, type LoginItem } from "@nopass/types";

import { decryptItem, encryptItem } from "../aes-gcm";
import { computeEmailHash, deriveMasterKey, stretchMasterKey } from "../kdf";
import { changeMasterPassword, IncorrectPasswordError, type PasswordChangeApi } from "../password-change";
import { createOpaqueRegistration } from "../password-login";

const EMAIL = "alice@example.com";
const OLD = "correct horse battery staple";
const NEW = "a different long passphrase";
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

/** Server half built on serenity's opaque-ke server, holding one item under the old keys. */
async function fakeServer() {
  await opaque.ready;
  const serverSetup = opaque.server.createSetup();
  const userIdentifier = computeEmailHash(EMAIL);
  const record = await createOpaqueRegistration(OLD, KSF, async (registrationRequest) =>
    opaque.server.createRegistrationResponse({ serverSetup, userIdentifier, registrationRequest }),
  );
  const oldKeys = await stretchMasterKey(await deriveMasterKey(OLD, EMAIL, DEFAULT_KDF_PARAMS), EMAIL);
  const blob = await encryptItem(ITEM, oldKeys.vaultEncKey, oldKeys.vaultMacKey);
  let loginState = "";

  const api: PasswordChangeApi = {
    passwordChangeStart: vi.fn(async (req) => {
      const login = opaque.server.startLogin({
        serverSetup,
        registrationRecord: record,
        startLoginRequest: req.startLoginRequest,
        userIdentifier,
      });
      loginState = login.serverLoginState;
      const { registrationResponse } = opaque.server.createRegistrationResponse({
        serverSetup,
        userIdentifier,
        registrationRequest: req.registrationRequest,
      });
      return {
        changeId: "change-1",
        loginResponse: login.loginResponse,
        kdfParams: KSF,
        registrationResponse,
        items: [{ id: "item-1", vaultId: "v", userId: "u", itemType: "login" as const, ...blob, version: 1, deletedAt: null, createdAt: "", updatedAt: "" }],
      };
    }),
    passwordChangeFinish: vi.fn(async (req) => {
      opaque.server.finishLogin({ serverLoginState: loginState, finishLoginRequest: req.finishLoginRequest });
    }),
  };
  return { api };
}

describe("changeMasterPassword", () => {
  it("proves the current password and re-encrypts every item under the new keys", async () => {
    const { api } = await fakeServer();

    const newKeys = await changeMasterPassword(api, {
      email: EMAIL,
      sessionToken: "t",
      currentPassword: OLD,
      newPassword: NEW,
    });

    const sent = vi.mocked(api.passwordChangeFinish).mock.calls[0]![0];
    expect(sent.items).toHaveLength(1);
    // Returned keys are the ones a fresh login with the new password derives…
    const fresh = await stretchMasterKey(await deriveMasterKey(NEW, EMAIL, DEFAULT_KDF_PARAMS), EMAIL);
    // …and they open what was uploaded.
    await expect(decryptItem(sent.items[0]!, fresh.vaultEncKey, fresh.vaultMacKey)).resolves.toEqual(ITEM);
    await expect(decryptItem(sent.items[0]!, newKeys.vaultEncKey, newKeys.vaultMacKey)).resolves.toEqual(ITEM);
  }, 60_000);

  it("stops before uploading anything when the current password is wrong", async () => {
    const { api } = await fakeServer();

    await expect(
      changeMasterPassword(api, { email: EMAIL, sessionToken: "t", currentPassword: "wrong", newPassword: NEW }),
    ).rejects.toBeInstanceOf(IncorrectPasswordError);
    expect(api.passwordChangeFinish).not.toHaveBeenCalled();
  }, 60_000);
});
