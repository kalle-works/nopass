/** Auth endpoints of a running API, for the integration tests that need one. */
import type {
  OpaqueRegisterFinishRequest,
  OpaqueRegisterStartRequest,
  OpaqueRegisterStartResponse,
  RegisterResponse,
} from "@nopass/types";

import type { AccountKeyApi } from "../../account-key";
import type { PasswordChangeApi } from "../../password-change";
import type { PasswordAuthApi } from "../../password-login";

export type ApiCall = (method: string, path: string, body?: unknown, token?: string) => Promise<any>;

export function liveAuthApi(call: ApiCall): PasswordAuthApi & AccountKeyApi & PasswordChangeApi & {
  opaqueRegisterStart(req: OpaqueRegisterStartRequest): Promise<OpaqueRegisterStartResponse>;
  opaqueRegisterFinish(req: OpaqueRegisterFinishRequest): Promise<RegisterResponse>;
} {
  return {
    opaqueRegisterStart: (req) => call("POST", "/auth/opaque/register/start", req),
    opaqueRegisterFinish: (req) => call("POST", "/auth/opaque/register/finish", req),
    opaqueLoginStart: (req) => call("POST", "/auth/opaque/login/start", req),
    opaqueLoginFinish: (req) => call("POST", "/auth/opaque/login/finish", req),
    opaqueReregisterStart: (req, token) => call("POST", "/auth/opaque/reregister/start", req, token),
    opaqueReregisterFinish: (req, token) => call("POST", "/auth/opaque/reregister/finish", req, token),
    setAccountKey: (req, token) => call("PUT", "/auth/account-key", req, token),
    passwordChangeStart: (req, token) => call("POST", "/auth/password/start", req, token),
    passwordChangeFinish: (req, token) => call("POST", "/auth/password/finish", req, token),
    srpInit: (req) => call("POST", "/auth/srp/init", req),
    srpVerify: (req) => call("POST", "/auth/srp/verify", req),
  };
}
