/**
 * Master-password login and registration over OPAQUE (RFC 9807), with the
 * SRP fallback and automatic upgrade for accounts created before OPAQUE.
 *
 * The OPAQUE client is @serenity-kit/opaque: the wasm build of opaque-ke, the
 * same library the server runs, so the two can't drift apart. The key
 * stretching function is Argon2id with the account's KDF parameters, which
 * the server returns at login start. See docs/auth.md.
 */
import * as opaque from "@serenity-kit/opaque";
import type {
  KdfParams,
  LoginResponse,
  OpaqueLoginFinishRequest,
  OpaqueLoginStartRequest,
  OpaqueLoginStartResponse,
  OpaqueRegisterStartRequest,
  OpaqueRegisterStartResponse,
  OpaqueReregisterFinishRequest,
  SrpInitRequest,
  SrpInitResponse,
  SrpVerifyRequest,
  SrpVerifyResponse,
} from "@nopass/types";

import { computeEmailHash } from "./kdf";
import { srpStep1, srpStep2 } from "./srp-client";

/** The auth endpoints a login needs; each app's API client provides them. */
export interface PasswordAuthApi {
  opaqueLoginStart(req: OpaqueLoginStartRequest): Promise<OpaqueLoginStartResponse>;
  opaqueLoginFinish(req: OpaqueLoginFinishRequest): Promise<LoginResponse>;
  srpInit(req: SrpInitRequest): Promise<SrpInitResponse>;
  srpVerify(req: SrpVerifyRequest): Promise<SrpVerifyResponse>;
  opaqueReregisterStart(
    req: OpaqueRegisterStartRequest,
    token: string,
  ): Promise<OpaqueRegisterStartResponse>;
  opaqueReregisterFinish(req: OpaqueReregisterFinishRequest, token: string): Promise<void>;
}

function keyStretching(params: KdfParams) {
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
 * registration request to whichever route applies (new account, SRP upgrade,
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
    keyStretching: keyStretching(kdfParams),
  });
  return registrationRecord;
}

export interface PasswordLoginOptions {
  email: string;
  password: string;
  /** Links the session to a trusted device the client registered earlier. */
  deviceId?: string;
}

/**
 * Logs in with the master password. Tries OPAQUE first; if the client can't
 * open the server's response (wrong password, or an account still on SRP —
 * the server answers both the same way) it falls back to SRP. An SRP success
 * is upgraded to OPAQUE straight away, which deletes the SRP verifier.
 *
 * Throws whatever the API client throws for the failed SRP verify (a 401)
 * when the password is wrong.
 */
export async function loginWithPassword(
  api: PasswordAuthApi,
  { email, password, deviceId }: PasswordLoginOptions,
): Promise<LoginResponse> {
  await opaque.ready;
  const emailHash = computeEmailHash(email);
  const device = deviceId ? { deviceId } : {};

  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });
  const started = await api.opaqueLoginStart({ emailHash, startLoginRequest });
  const finished = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: started.loginResponse,
    password,
    keyStretching: keyStretching(started.kdfParams),
  });
  if (finished) {
    return api.opaqueLoginFinish({
      loginId: started.loginId,
      finishLoginRequest: finished.finishLoginRequest,
      ...device,
    });
  }

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
  try {
    const registrationRecord = await createOpaqueRegistration(password, init.kdfParams, (registrationRequest) =>
      api.opaqueReregisterStart({ emailHash, registrationRequest }, session.sessionToken),
    );
    await api.opaqueReregisterFinish({ registrationRecord }, session.sessionToken);
  } catch {
    // The login itself succeeded; the upgrade is retried on the next login.
  }
  return session;
}
