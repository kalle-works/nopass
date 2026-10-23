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
import { assertKdfFloor } from "./account-state";
import { IncorrectPasswordError, keyStretching } from "./password-login";
import { computeEmailHash, deriveMasterKey } from "./kdf";

export interface PasswordChangeApi {
  passwordChangeStart(req: PasswordChangeStartRequest, token: string): Promise<PasswordChangeStartResponse>;
  passwordChangeFinish(req: PasswordChangeFinishRequest, token: string): Promise<void>;
}

export interface PasswordChangeOptions {
  email: string;
  sessionToken: string;
  currentPassword: string;
  newPassword: string;
}

export async function changeMasterPassword(
  api: PasswordChangeApi,
  { email, sessionToken, currentPassword, newPassword }: PasswordChangeOptions,
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
    keyStretching: keyStretching(assertKdfFloor(started.kdfParams)),
  });
  if (!proof) throw new IncorrectPasswordError();
  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState: registration.clientRegistrationState,
    registrationResponse: started.registrationResponse,
    password: newPassword,
    keyStretching: keyStretching(assertKdfFloor(started.kdfParams)),
  });

  const oldMaster = await deriveMasterKey(currentPassword, email, DEFAULT_KDF_PARAMS);
  const newMaster = await deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
  const account = await unwrapAccountKey(started, oldMaster, email);
  try {
    const rewrapped = await wrapAccountKey(account, newMaster, email);
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
