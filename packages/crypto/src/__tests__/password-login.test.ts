// @vitest-environment node
import * as opaque from "@serenity-kit/opaque";
import { describe, expect, it } from "vitest";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";

import { memoryAccountState, WeakKdfParamsError } from "../account-state";
import { computeEmailHash } from "../kdf";
import { createOpaqueRegistration, IncorrectPasswordError, loginWithPassword } from "../password-login";
import { fakeServer } from "./support/fake-server";

const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";

async function opaqueAccount() {
  const server = await fakeServer(EMAIL);
  server.account.opaqueRecord = await createOpaqueRegistration(PASSWORD, DEFAULT_KDF_PARAMS, async (registrationRequest) =>
    opaque.server.createRegistrationResponse({
      serverSetup: server.serverSetup,
      userIdentifier: computeEmailHash(EMAIL),
      registrationRequest,
    }),
  );
  return server;
}

describe("loginWithPassword", () => {
  it("logs an OPAQUE account in without touching SRP and remembers it", async () => {
    const { api } = await opaqueAccount();
    const accountState = memoryAccountState();

    const result = await loginWithPassword(api, { email: EMAIL, password: PASSWORD, accountState });
    expect(result.method).toBe("opaque");
    expect(api.srpInit).not.toHaveBeenCalled();
    expect((await accountState.get(computeEmailHash(EMAIL))).opaque).toBe(true);
  });

  it("rejects a wrong password without sending an OPAQUE proof", async () => {
    const { api } = await opaqueAccount();

    await expect(
      loginWithPassword(api, { email: EMAIL, password: "wrong", accountState: memoryAccountState() }),
    ).rejects.toMatchObject({ status: 401 });
    expect(api.opaqueLoginFinish).not.toHaveBeenCalled();
  });

  it("never falls back to SRP for an account this device knows uses OPAQUE", async () => {
    // A server that hides the OPAQUE record and offers SRP is trying a downgrade.
    const server = await fakeServer(EMAIL);
    server.makeSrpAccount(EMAIL, PASSWORD);
    const accountState = memoryAccountState();
    await accountState.update(computeEmailHash(EMAIL), { opaque: true });

    await expect(loginWithPassword(server.api, { email: EMAIL, password: PASSWORD, accountState })).rejects.toBeInstanceOf(
      IncorrectPasswordError,
    );
    expect(server.api.srpInit).not.toHaveBeenCalled();
  });

  it("refuses KDF parameters below the defaults", async () => {
    const server = await opaqueAccount();
    server.account.kdfParams = { ...DEFAULT_KDF_PARAMS, memoryKib: 1024 };

    await expect(
      loginWithPassword(server.api, { email: EMAIL, password: PASSWORD, accountState: memoryAccountState() }),
    ).rejects.toBeInstanceOf(WeakKdfParamsError);
    expect(server.api.opaqueLoginFinish).not.toHaveBeenCalled();
  });

  it("logs an SRP account in over SRP, leaving the upgrade to unlockAccount", async () => {
    const server = await fakeServer(EMAIL);
    server.makeSrpAccount(EMAIL, PASSWORD);

    const result = await loginWithPassword(server.api, { email: EMAIL, password: PASSWORD, accountState: memoryAccountState() });
    expect(result.method).toBe("srp");
  });
});
