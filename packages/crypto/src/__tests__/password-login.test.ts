// @vitest-environment node
/**
 * The login flow against an in-memory server built from the same OPAQUE
 * library the API runs (serenity's server half is opaque-ke, like the Rust
 * API) and the Rust-compatible SRP math.
 */
import * as opaque from "@serenity-kit/opaque";
import { describe, expect, it, vi } from "vitest";
import type { KdfParams, LoginResponse } from "@nopass/types";

import { computeEmailHash } from "../kdf";
import { createOpaqueRegistration, loginWithPassword, type PasswordAuthApi } from "../password-login";
import { generateSrpRegistration } from "../srp-client";
import {
  base64ToHex,
  bytesToHex,
  computeRustServerS,
  generateRustServerEphemeral,
  hexToBase64,
  hexToBytes,
  rustM1,
  rustM2,
} from "./support/rust-srp-server";

const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery staple";
// Cheap, and deliberately not the defaults: a client that ignored the
// server's kdfParams would fail to open its own record.
const ACCOUNT_KDF: KdfParams = { type: "argon2id", memoryKib: 1024, iterations: 1, parallelism: 1 };
const DEFAULT_KDF: KdfParams = { type: "argon2id", memoryKib: 65536, iterations: 3, parallelism: 4 };

class HttpError extends Error {
  constructor(public readonly status: number) {
    super(`HTTP ${status}`);
  }
}

interface Account {
  emailHash: string;
  kdfParams: KdfParams;
  opaqueRecord?: string;
  srp?: { salt: string; verifierHex: string };
}

function session(): LoginResponse {
  return {
    sessionToken: "token",
    userId: "user",
    defaultVaultId: "vault",
    protectedSymmetricKey: "",
    protectedSymmetricKeyIv: "",
  };
}

/** Behaves like the API: fake OPAQUE record and fake SRP challenge for anyone without the real thing. */
async function fakeServer(account: Account) {
  await opaque.ready;
  const serverSetup = opaque.server.createSetup();
  const logins = new Map<string, string>();
  const srpSessions = new Map<string, { A: string; B: string; b: string }>();

  const api: PasswordAuthApi = {
    async opaqueLoginStart({ emailHash, startLoginRequest }) {
      const record = emailHash === account.emailHash ? account.opaqueRecord : undefined;
      const { serverLoginState, loginResponse } = opaque.server.startLogin({
        serverSetup,
        registrationRecord: record ?? null,
        startLoginRequest,
        userIdentifier: emailHash,
      });
      const loginId = crypto.randomUUID();
      logins.set(loginId, serverLoginState);
      return { loginId, loginResponse, kdfParams: record ? account.kdfParams : DEFAULT_KDF };
    },
    async opaqueLoginFinish({ loginId, finishLoginRequest }) {
      const serverLoginState = logins.get(loginId);
      if (!serverLoginState) throw new HttpError(401);
      opaque.server.finishLogin({ serverLoginState, finishLoginRequest });
      return session();
    },
    async srpInit({ emailHash, clientPublicA }) {
      const sessionId = crypto.randomUUID();
      const srp = emailHash === account.emailHash ? account.srp : undefined;
      const verifierHex = srp?.verifierHex ?? "02";
      const eph = generateRustServerEphemeral(verifierHex);
      if (srp) srpSessions.set(sessionId, { A: base64ToHex(clientPublicA), B: eph.public, b: eph.secret });
      return {
        sessionId,
        serverPublicB: hexToBase64(eph.public),
        srpSalt: srp?.salt ?? hexToBase64("00".repeat(32)),
        kdfParams: srp ? account.kdfParams : DEFAULT_KDF,
      };
    },
    async srpVerify({ sessionId, clientProofM1 }) {
      const s = srpSessions.get(sessionId);
      if (!s || !account.srp) throw new HttpError(401);
      const S = computeRustServerS(s.A, s.B, s.b, account.srp.verifierHex);
      const m1 = rustM1(s.A, s.B, S);
      if (bytesToHex(m1) !== base64ToHex(clientProofM1)) throw new HttpError(401);
      return { ...session(), serverProofM2: hexToBase64(bytesToHex(rustM2(s.A, m1, S))) };
    },
    async opaqueReregisterStart({ emailHash, registrationRequest }) {
      return opaque.server.createRegistrationResponse({
        serverSetup,
        userIdentifier: emailHash,
        registrationRequest,
      });
    },
    async opaqueReregisterFinish({ registrationRecord }) {
      account.opaqueRecord = registrationRecord;
      delete account.srp;
    },
  };

  for (const key of Object.keys(api) as (keyof PasswordAuthApi)[]) vi.spyOn(api, key);
  return { api, serverSetup };
}

async function opaqueAccount(): Promise<{ account: Account; api: PasswordAuthApi }> {
  const account: Account = { emailHash: computeEmailHash(EMAIL), kdfParams: ACCOUNT_KDF };
  const { api, serverSetup } = await fakeServer(account);
  account.opaqueRecord = await createOpaqueRegistration(PASSWORD, ACCOUNT_KDF, async (registrationRequest) =>
    opaque.server.createRegistrationResponse({
      serverSetup,
      userIdentifier: account.emailHash,
      registrationRequest,
    }),
  );
  return { account, api };
}

describe("loginWithPassword", () => {
  it("logs an OPAQUE account in without touching SRP", async () => {
    const { api } = await opaqueAccount();

    await expect(loginWithPassword(api, { email: EMAIL, password: PASSWORD })).resolves.toMatchObject({
      sessionToken: "token",
    });
    expect(api.opaqueLoginFinish).toHaveBeenCalledOnce();
    expect(api.srpInit).not.toHaveBeenCalled();
  });

  it("rejects a wrong password without sending an OPAQUE proof", async () => {
    const { api } = await opaqueAccount();

    await expect(loginWithPassword(api, { email: EMAIL, password: "wrong" })).rejects.toMatchObject({
      status: 401,
    });
    expect(api.opaqueLoginFinish).not.toHaveBeenCalled();
    expect(api.opaqueReregisterFinish).not.toHaveBeenCalled();
  });

  it("logs an SRP account in and upgrades it so the next login is OPAQUE", async () => {
    const { srpSalt, srpVerifier } = generateSrpRegistration(EMAIL, PASSWORD);
    const account: Account = {
      emailHash: computeEmailHash(EMAIL),
      kdfParams: ACCOUNT_KDF,
      srp: { salt: srpSalt, verifierHex: bytesToHex(hexToBytes(base64ToHex(srpVerifier))) },
    };
    const { api } = await fakeServer(account);

    await loginWithPassword(api, { email: EMAIL, password: PASSWORD });
    expect(api.opaqueReregisterFinish).toHaveBeenCalledOnce();
    expect(account.srp).toBeUndefined();

    vi.mocked(api.srpInit).mockClear();
    await loginWithPassword(api, { email: EMAIL, password: PASSWORD });
    expect(api.srpInit).not.toHaveBeenCalled();
    expect(api.opaqueLoginFinish).toHaveBeenCalledOnce();
  });
});
