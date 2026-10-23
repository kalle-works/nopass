/**
 * Master-password change. Items are encrypted under the password-independent
 * account key, so a change only re-wraps that key: open it with the current
 * password, wrap it under the new one, and register a new OPAQUE record. The
 * server checks a fresh OPAQUE proof of the current password, swaps record
 * and wrap in one transaction and revokes every other session. The vault keys
 * in memory and the recovery kit stay valid.
 */
import * as opaque from "@serenity-kit/opaque";
import {
  DEFAULT_KDF_PARAMS,
  type PasswordChangeFinishRequest,
  type PasswordChangeStartRequest,
  type PasswordChangeStartResponse,
} from "@nopass/types";

import { unwrapAccountKey, wrapAccountKey, zeroAccount } from "./account-key";
import { computeEmailHash, deriveMasterKey } from "./kdf";

export interface PasswordChangeApi {
  passwordChangeStart(req: PasswordChangeStartRequest, token: string): Promise<PasswordChangeStartResponse>;
  passwordChangeFinish(req: PasswordChangeFinishRequest, token: string): Promise<void>;
}

/** The current password didn't open the server's login response. */
export class IncorrectPasswordError extends Error {
  constructor() {
    super("Current master password is incorrect.");
    this.name = "IncorrectPasswordError";
  }
}

export interface PasswordChangeOptions {
  email: string;
  userId: string;
  sessionToken: string;
  currentPassword: string;
  newPassword: string;
}

function keyStretching(params: { iterations: number; memoryKib: number; parallelism: number }) {
  return {
    "argon2id-custom": { iterations: params.iterations, memory: params.memoryKib, parallelism: params.parallelism },
  } as const;
}

export async function changeMasterPassword(
  api: PasswordChangeApi,
  { email, userId, sessionToken, currentPassword, newPassword }: PasswordChangeOptions,
): Promise<void> {
  await opaque.ready;
  const login = opaque.client.startLogin({ password: currentPassword });
  const registration = opaque.client.startRegistration({ password: newPassword });
  const started = await api.passwordChangeStart(
    {
      emailHash: computeEmailHash(email),
      startLoginRequest: login.startLoginRequest,
      registrationRequest: registration.registrationRequest,
    },
    sessionToken,
  );

  const proof = opaque.client.finishLogin({
    clientLoginState: login.clientLoginState,
    loginResponse: started.loginResponse,
    password: currentPassword,
    keyStretching: keyStretching(started.kdfParams),
  });
  if (!proof) throw new IncorrectPasswordError();
  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState: registration.clientRegistrationState,
    registrationResponse: started.registrationResponse,
    password: newPassword,
    keyStretching: keyStretching(started.kdfParams),
  });

  const oldMaster = await deriveMasterKey(currentPassword, email, DEFAULT_KDF_PARAMS);
  const newMaster = await deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
  const account = await unwrapAccountKey(started, oldMaster, email, userId);
  try {
    const rewrapped = await wrapAccountKey(account, newMaster, email, userId);
    await api.passwordChangeFinish(
      {
        changeId: started.changeId,
        finishLoginRequest: proof.finishLoginRequest,
        registrationRecord,
        ...rewrapped,
      },
      sessionToken,
    );
  } finally {
    zeroAccount(account);
    oldMaster.fill(0);
    newMaster.fill(0);
  }
}
