/**
 * One account behind an in-memory server that behaves like the API: OPAQUE
 * via serenity's server half (opaque-ke, like the Rust API), SRP via the
 * Rust-compatible math, fake responses for anything it doesn't hold.
 */
import * as opaque from "@serenity-kit/opaque";
import { vi } from "vitest";
import { DEFAULT_KDF_PARAMS, type KdfParams, type LoginResponse, type RecoveryCompleteRequest } from "@nopass/types";

import type { AccountKeyApi } from "../../account-key";
import { computeEmailHash } from "../../kdf";
import type { PasswordChangeApi } from "../../password-change";
import type { PasswordAuthApi } from "../../password-login";
import { generateSrpRegistration } from "../../srp-client";
import {
  base64ToHex,
  bytesToHex,
  computeRustServerS,
  generateRustServerEphemeral,
  hexToBase64,
  hexToBytes,
  rustM1,
  rustM2,
} from "./rust-srp-server";

export class HttpError extends Error {
  constructor(public readonly status: number) {
    super(`HTTP ${status}`);
  }
}

export interface ServerAccount {
  emailHash: string;
  kdfParams: KdfParams;
  opaqueRecord?: string | undefined;
  srp?: { salt: string; verifierHex: string } | undefined;
  wrappedAccountKey?: string | undefined;
  wrappedAccountKeyIv?: string | undefined;
  protectedPrivateKey?: string | undefined;
  protectedPrivateKeyIv?: string | undefined;
}

export type FakeApi = PasswordAuthApi & AccountKeyApi & PasswordChangeApi;

export async function fakeServer(email: string) {
  await opaque.ready;
  const serverSetup = opaque.server.createSetup();
  const account: ServerAccount = { emailHash: computeEmailHash(email), kdfParams: DEFAULT_KDF_PARAMS };
  const logins = new Map<string, string>();
  const srpSessions = new Map<string, { A: string; B: string; b: string }>();
  const id = () => crypto.randomUUID();
  const credentialId = account.emailHash;

  const session = (): LoginResponse => ({
    sessionToken: "token",
    userId: "user",
    defaultVaultId: "vault",
    protectedSymmetricKey: "",
    protectedSymmetricKeyIv: "",
    protectedPrivateKey: account.protectedPrivateKey ?? null,
    protectedPrivateKeyIv: account.protectedPrivateKeyIv ?? null,
    wrappedAccountKey: account.wrappedAccountKey ?? null,
    wrappedAccountKeyIv: account.wrappedAccountKeyIv ?? null,
  });

  const startLogin = (emailHash: string, startLoginRequest: string) => {
    const record = emailHash === account.emailHash ? account.opaqueRecord : undefined;
    const { serverLoginState, loginResponse } = opaque.server.startLogin({
      serverSetup,
      registrationRecord: record ?? null,
      startLoginRequest,
      userIdentifier: emailHash,
    });
    const loginId = id();
    logins.set(loginId, serverLoginState);
    return { loginId, loginResponse, kdfParams: record ? account.kdfParams : DEFAULT_KDF_PARAMS };
  };
  const finishLogin = (loginId: string, finishLoginRequest: string) => {
    const serverLoginState = logins.get(loginId);
    logins.delete(loginId);
    if (!serverLoginState) throw new HttpError(401);
    try {
      opaque.server.finishLogin({ serverLoginState, finishLoginRequest });
    } catch {
      throw new HttpError(401);
    }
  };
  const srpChallenge = (clientPublicA: string) => {
    const sessionId = id();
    const eph = generateRustServerEphemeral(account.srp?.verifierHex ?? "02");
    if (account.srp) srpSessions.set(sessionId, { A: base64ToHex(clientPublicA), B: eph.public, b: eph.secret });
    return { sessionId, serverPublicB: hexToBase64(eph.public), srpSalt: account.srp?.salt ?? hexToBase64("00".repeat(32)) };
  };
  const srpCheck = (sessionId: string, clientProofM1: string) => {
    const s = srpSessions.get(sessionId);
    srpSessions.delete(sessionId);
    if (!s || !account.srp) throw new HttpError(401);
    const S = computeRustServerS(s.A, s.B, s.b, account.srp.verifierHex);
    const m1 = rustM1(s.A, s.B, S);
    if (bytesToHex(m1) !== base64ToHex(clientProofM1)) throw new HttpError(401);
    return hexToBase64(bytesToHex(rustM2(s.A, m1, S)));
  };
  const registrationResponse = (registrationRequest: string) =>
    opaque.server.createRegistrationResponse({ serverSetup, userIdentifier: credentialId, registrationRequest });

  const api: FakeApi = {
    opaqueLoginStart: async ({ emailHash, startLoginRequest }) => startLogin(emailHash, startLoginRequest),
    opaqueLoginFinish: async ({ loginId, finishLoginRequest }) => {
      finishLogin(loginId, finishLoginRequest);
      return session();
    },
    srpInit: async ({ clientPublicA }) => ({ ...srpChallenge(clientPublicA), kdfParams: account.kdfParams }),
    srpVerify: async ({ sessionId, clientProofM1 }) => ({ ...session(), serverProofM2: srpCheck(sessionId, clientProofM1) }),
    proofStart: async ({ emailHash, startLoginRequest }) => {
      const { loginId, ...rest } = startLogin(emailHash, startLoginRequest);
      return { proofId: loginId, ...rest };
    },
    setAccountKey: async (req) => {
      finishLogin(req.proof.proofId, req.proof.finishLoginRequest);
      if (account.wrappedAccountKey) throw new HttpError(409);
      Object.assign(account, {
        wrappedAccountKey: req.wrappedAccountKey,
        wrappedAccountKeyIv: req.wrappedAccountKeyIv,
        protectedPrivateKey: req.protectedPrivateKey ?? account.protectedPrivateKey,
        protectedPrivateKeyIv: req.protectedPrivateKeyIv ?? account.protectedPrivateKeyIv,
      });
    },
    upgradeStart: async ({ clientPublicA, registrationRequest }) => {
      if (!account.srp) throw new HttpError(409);
      const { sessionId, ...challenge } = srpChallenge(clientPublicA);
      return {
        upgradeId: sessionId,
        ...challenge,
        kdfParams: account.kdfParams,
        registrationResponse: registrationResponse(registrationRequest).registrationResponse,
      };
    },
    upgradeFinish: async (req) => {
      const serverProofM2 = srpCheck(req.upgradeId, req.clientProofM1);
      Object.assign(account, {
        opaqueRecord: req.registrationRecord,
        srp: undefined,
        wrappedAccountKey: req.wrappedAccountKey,
        wrappedAccountKeyIv: req.wrappedAccountKeyIv,
        protectedPrivateKey: req.protectedPrivateKey ?? account.protectedPrivateKey,
        protectedPrivateKeyIv: req.protectedPrivateKeyIv ?? account.protectedPrivateKeyIv,
      });
      return { serverProofM2 };
    },
    passwordChangeStart: async (req) => {
      const { loginId, ...login } = startLogin(req.emailHash, req.startLoginRequest);
      return {
        changeId: loginId,
        ...login,
        registrationResponse: registrationResponse(req.registrationRequest).registrationResponse,
        wrappedAccountKey: account.wrappedAccountKey!,
        wrappedAccountKeyIv: account.wrappedAccountKeyIv!,
      };
    },
    passwordChangeFinish: async (req) => {
      finishLogin(req.changeId, req.finishLoginRequest);
      Object.assign(account, {
        opaqueRecord: req.registrationRecord,
        wrappedAccountKey: req.wrappedAccountKey,
        wrappedAccountKeyIv: req.wrappedAccountKeyIv,
      });
    },
  };
  for (const key of Object.keys(api) as (keyof FakeApi)[]) vi.spyOn(api, key);

  return {
    api,
    account,
    serverSetup,
    /** Pre-OPAQUE account: only an SRP verifier. */
    makeSrpAccount(email: string, password: string) {
      const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);
      account.srp = { salt: srpSalt, verifierHex: bytesToHex(hexToBytes(base64ToHex(srpVerifier))) };
    },
    /** Recovery endpoints, for completeAccountRecovery. */
    recoveryApi(onComplete: (req: RecoveryCompleteRequest) => void) {
      return {
        opaqueStart: async (req: { registrationRequest: string }) => registrationResponse(req.registrationRequest),
        complete: async (req: RecoveryCompleteRequest) => {
          Object.assign(account, {
            opaqueRecord: req.registrationRecord,
            srp: undefined,
            wrappedAccountKey: req.wrappedAccountKey,
            wrappedAccountKeyIv: req.wrappedAccountKeyIv,
            protectedPrivateKey: req.protectedPrivateKey ?? account.protectedPrivateKey,
            protectedPrivateKeyIv: req.protectedPrivateKeyIv ?? account.protectedPrivateKeyIv,
          });
          onComplete(req);
        },
      };
    },
  };
}
