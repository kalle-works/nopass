/**
 * Master-password login and registration over OPAQUE (RFC 9807), with the
 * SRP fallback for accounts created before OPAQUE.
 *
 * The OPAQUE client is @serenity-kit/opaque: the wasm build of opaque-ke, the
 * same library the server runs, so the two can't drift apart. The key
 * stretching function is Argon2id with the account's KDF parameters, which
 * the server returns at login start and which must not be weaker than the
 * defaults. Upgrading an SRP account to OPAQUE happens in `unlockAccount`,
 * with a fresh SRP proof. See docs/auth.md.
 */
import * as opaque from "@serenity-kit/opaque";
import type {
  KdfParams,
  LoginResponse,
  OpaqueLoginFinishRequest,
  OpaqueLoginStartRequest,
  OpaqueLoginStartResponse,
  OpaqueRegisterStartResponse,
  PasswordProof,
  PasswordProofStartRequest,
  PasswordProofStartResponse,
  ProofPurpose,
  SrpInitRequest,
  SrpInitResponse,
  SrpVerifyRequest,
  SrpVerifyResponse,
} from "@nopass/types";

import { assertKdfFloor, type AccountStateStore } from "./account-state";
import { computeEmailHash } from "./kdf";
import { srpStep1, srpStep2 } from "./srp-client";

/** The auth endpoints a login needs; each app's API client provides them. */
export interface PasswordAuthApi {
  opaqueLoginStart(req: OpaqueLoginStartRequest): Promise<OpaqueLoginStartResponse>;
  opaqueLoginFinish(req: OpaqueLoginFinishRequest): Promise<LoginResponse>;
  srpInit(req: SrpInitRequest): Promise<SrpInitResponse>;
  srpVerify(req: SrpVerifyRequest): Promise<SrpVerifyResponse>;
}

export interface PasswordProofApi {
  proofStart(req: PasswordProofStartRequest, token: string): Promise<PasswordProofStartResponse>;
}

/** Wrong password (or unknown account) — the two are indistinguishable by design. */
export class IncorrectPasswordError extends Error {
  readonly status = 401;
  constructor() {
    super("Incorrect email or master password.");
    this.name = "IncorrectPasswordError";
  }
}

export function keyStretching(params: KdfParams) {
  return {
    "argon2id-custom": {
      iterations: params.iterations,
      memory: params.memoryKib,
      parallelism: params.parallelism,
    },
  } as const;
}

/**
 * Runs the client side of an OPAQUE registration. `start` sends the
 * registration request to whichever route applies (new account, upgrade,
 * recovery) and returns the server's response; the resulting record goes to
 * the matching finish call.
 */
export async function createOpaqueRegistration(
  password: string,
  kdfParams: KdfParams,
  start: (registrationRequest: string) => Promise<OpaqueRegisterStartResponse>,
): Promise<string> {
  await opaque.ready;
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
    password,
  });
  const { registrationResponse } = await start(registrationRequest);
  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse,
    password,
    keyStretching: keyStretching(assertKdfFloor(kdfParams)),
  });
  return registrationRecord;
}

export interface PasswordLoginOptions {
  email: string;
  password: string;
  /** What this device remembers about the account; see account-state.ts */
  accountState: AccountStateStore;
  /** Links the session to a trusted device the client registered earlier. */
  deviceId?: string;
}

/** A login, and which protocol it used — an SRP login still needs the upgrade in `unlockAccount`. */
export type PasswordLoginResult = LoginResponse & { method: "opaque" | "srp" };

/**
 * Logs in with the master password. Tries OPAQUE first; if the client can't
 * open the server's response (wrong password, or an account still on SRP —
 * the server answers both the same way) it falls back to SRP, unless this
 * device has seen the account use OPAQUE, in which case a fallback could
 * only be a downgrade and the password is reported wrong.
 */
export async function loginWithPassword(
  api: PasswordAuthApi,
  { email, password, accountState, deviceId }: PasswordLoginOptions,
): Promise<PasswordLoginResult> {
  await opaque.ready;
  const emailHash = computeEmailHash(email);
  const device = deviceId ? { deviceId } : {};

  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const started = await api.opaqueLoginStart({ emailHash, startLoginRequest });
  const finished = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: started.loginResponse,
    password,
    keyStretching: keyStretching(assertKdfFloor(started.kdfParams)),
  });
  if (finished) {
    const session = await api.opaqueLoginFinish({
      loginId: started.loginId,
      finishLoginRequest: finished.finishLoginRequest,
      ...device,
    });
    await accountState.update(emailHash, { opaque: true });
    return { ...session, method: "opaque" };
  }

  if ((await accountState.get(emailHash)).opaque) throw new IncorrectPasswordError();

  const step1 = srpStep1();
  const init = await api.srpInit({ emailHash, clientPublicA: step1.clientPublicA });
  const step2 = srpStep2(email, password, init.srpSalt, init.serverPublicB, step1.privateSession);
  const verified = await api.srpVerify({
    sessionId: init.sessionId,
    clientProofM1: step2.clientProofM1,
    ...device,
  });
  step2.verifyServerProof(verified.serverProofM2);
  const { serverProofM2: _, ...session } = verified;
  return { ...session, method: "srp" };
}

/**
 * A fresh OPAQUE proof of the password for an authenticated request that
 * replaces key material. Throws IncorrectPasswordError if the password
 * doesn't open the server's response.
 */
export async function provePassword(
  api: PasswordProofApi,
  {
    email,
    password,
    sessionToken,
    purpose,
  }: { email: string; password: string; sessionToken: string; purpose: ProofPurpose },
): Promise<PasswordProof> {
  await opaque.ready;
  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const started = await api.proofStart({ emailHash: computeEmailHash(email), startLoginRequest, purpose }, sessionToken);
  const finished = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: started.loginResponse,
    password,
    keyStretching: keyStretching(assertKdfFloor(started.kdfParams)),
  });
  if (!finished) throw new IncorrectPasswordError();
  return { proofId: started.proofId, finishLoginRequest: finished.finishLoginRequest };
}
