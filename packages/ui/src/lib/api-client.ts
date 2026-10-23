/**
 * Typed API client for nopass-api.
 * All responses are typed via @nopass/types.
 * The base URL is injected so the same client works on web, desktop, and extension.
 */
import type {
  AcceptInviteRequest,
  ActivityEventInfo,
  BillingStatus,
  CheckoutSessionResponse,
  ConflictResponse,
  CreateCheckoutRequest,
  CreateOrgRequest,
  CreatePortalRequest,
  CreateShareRequest,
  CreateVaultRequest,
  CreateShareResponse,
  CreateVaultItemRequest,
  DeviceInfo,
  EncryptedVaultItem,
  InviteMemberRequest,
  MoveItemRequest,
  OrgDetails,
  OrgSummary,
  PendingInvite,
  RewrapRequest,
  RotateKeyRequest,
  PortalSessionResponse,
  PublicKeyResponse,
  RecoveryCompleteRequest,
  RecoveryInitRequest,
  RecoveryInitResponse,
  RecoveryStatusResponse,
  LoginResponse,
  OpaqueLoginFinishRequest,
  OpaqueLoginStartRequest,
  OpaqueLoginStartResponse,
  OpaqueRegisterFinishRequest,
  OpaqueRegisterStartRequest,
  OpaqueRegisterStartResponse,
  OpaqueReregisterFinishRequest,
  PasswordChangeFinishRequest,
  PasswordChangeStartRequest,
  PasswordChangeStartResponse,
  SetAccountKeyRequest,
  RecoveryOpaqueStartRequest,
  RegisterDeviceRequest,
  RegisterResponse,
  SetIdentityRequest,
  SetRecoveryRequest,
  ShareInfo,
  SrpInitRequest,
  SrpInitResponse,
  SrpVerifyRequest,
  SrpVerifyResponse,
  SyncRequest,
  SyncResponse,
  UpdateVaultItemRequest,
  VaultFormatMarker,
  VaultInfo,
  ViewShareResponse,
} from "@nopass/types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class ConflictError extends ApiError {
  constructor(public readonly serverVersion: number) {
    super("conflict", 409);
  }
}

async function request<T>(
  baseUrl: string,
  path: string,
  options: RequestInit & { token?: string | undefined },
): Promise<T> {
  const headers: HeadersInit = { "Content-Type": "application/json" };
  if (options.token) headers["Authorization"] = `Bearer ${options.token}`;

  const res = await fetch(`${baseUrl}/v1${path}`, { ...options, headers });

  if (!res.ok) {
    if (res.status === 409) {
      const body = (await res.json()) as ConflictResponse;
      throw new ConflictError(body.serverVersion);
    }
    const body = (await res.json().catch(() => ({ error: res.statusText }))) as { error: string };
    throw new ApiError(body.error, res.status);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export function createApiClient(baseUrl: string) {
  const get = <T>(path: string, token?: string) =>
    request<T>(baseUrl, path, { method: "GET", token });

  const post = <T>(path: string, body: unknown, token?: string) =>
    request<T>(baseUrl, path, { method: "POST", body: JSON.stringify(body), token });

  const put = <T>(path: string, body: unknown, token?: string) =>
    request<T>(baseUrl, path, { method: "PUT", body: JSON.stringify(body), token });

  const del = <T>(path: string, token?: string) =>
    request<T>(baseUrl, path, { method: "DELETE", token });

  return {
    auth: {
      opaqueRegisterStart: (req: OpaqueRegisterStartRequest) =>
        post<OpaqueRegisterStartResponse>("/auth/opaque/register/start", req),
      opaqueRegisterFinish: (req: OpaqueRegisterFinishRequest) =>
        post<RegisterResponse>("/auth/opaque/register/finish", req),
      opaqueLoginStart: (req: OpaqueLoginStartRequest) =>
        post<OpaqueLoginStartResponse>("/auth/opaque/login/start", req),
      opaqueLoginFinish: (req: OpaqueLoginFinishRequest) =>
        post<LoginResponse>("/auth/opaque/login/finish", req),
      opaqueReregisterStart: (req: OpaqueRegisterStartRequest, token: string) =>
        post<OpaqueRegisterStartResponse>("/auth/opaque/reregister/start", req, token),
      opaqueReregisterFinish: (req: OpaqueReregisterFinishRequest, token: string) =>
        post<void>("/auth/opaque/reregister/finish", req, token),
      setAccountKey: (req: SetAccountKeyRequest, token: string) =>
        request<void>(baseUrl, "/auth/account-key", { method: "PUT", body: JSON.stringify(req), token }),
      passwordChangeStart: (req: PasswordChangeStartRequest, token: string) =>
        post<PasswordChangeStartResponse>("/auth/password/start", req, token),
      passwordChangeFinish: (req: PasswordChangeFinishRequest, token: string) =>
        post<void>("/auth/password/finish", req, token),
      // Legacy SRP, used only by loginWithPassword's fallback for unmigrated accounts
      srpInit: (req: SrpInitRequest) => post<SrpInitResponse>("/auth/srp/init", req),
      srpVerify: (req: SrpVerifyRequest) => post<SrpVerifyResponse>("/auth/srp/verify", req),
      logout: (token: string) => post<void>("/auth/logout", {}, token),
    },
    recovery: {
      status: (token: string) => get<RecoveryStatusResponse>("/auth/recovery", token),
      set: (req: SetRecoveryRequest, token: string) => put<void>("/auth/recovery", req, token),
      disable: (token: string) => del<void>("/auth/recovery", token),
      init: (req: RecoveryInitRequest) => post<RecoveryInitResponse>("/auth/recovery/init", req),
      opaqueStart: (req: RecoveryOpaqueStartRequest) =>
        post<OpaqueRegisterStartResponse>("/auth/recovery/opaque/start", req),
      complete: (req: RecoveryCompleteRequest) => post<void>("/auth/recovery/complete", req),
    },
    activity: {
      list: (token: string) => get<ActivityEventInfo[]>("/activity", token),
    },
    devices: {
      list: (token: string) => get<DeviceInfo[]>("/devices", token),
      register: (req: RegisterDeviceRequest, token: string) =>
        post<{ deviceId: string }>("/devices", req, token),
      remove: (deviceId: string, token: string) => del<void>(`/devices/${deviceId}`, token),
      signOutOthers: (token: string) =>
        post<{ signedOut: number }>("/devices/sign-out-others", {}, token),
    },
    vault: {
      list: (token: string) => get<VaultInfo[]>("/vaults", token),
      createVault: (req: CreateVaultRequest, token: string) =>
        post<VaultInfo>("/vaults", req, token),
      renameVault: (vaultId: string, req: CreateVaultRequest, token: string) =>
        put<void>(`/vaults/${vaultId}`, req, token),
      deleteVault: (vaultId: string, token: string) => del<void>(`/vaults/${vaultId}`, token),
      moveItem: (vaultId: string, itemId: string, req: MoveItemRequest, token: string) =>
        post<void>(`/vaults/${vaultId}/items/${itemId}/move`, req, token),
      items: (vaultId: string, token: string, since?: string) =>
        get<EncryptedVaultItem[]>(
          `/vaults/${vaultId}/items${since ? `?since=${encodeURIComponent(since)}` : ""}`,
          token,
        ),
      create: (vaultId: string, req: CreateVaultItemRequest, token: string) =>
        post<EncryptedVaultItem>(`/vaults/${vaultId}/items`, req, token),
      update: (vaultId: string, itemId: string, req: UpdateVaultItemRequest, token: string) =>
        put<{ version: number; updatedAt: string }>(
          `/vaults/${vaultId}/items/${itemId}`,
          req,
          token,
        ),
      delete: (vaultId: string, itemId: string, token: string) =>
        del<void>(`/vaults/${vaultId}/items/${itemId}`, token),
    },
    shares: {
      create: (req: CreateShareRequest, token: string) =>
        post<CreateShareResponse>("/shares", req, token),
      list: (token: string) => get<ShareInfo[]>("/shares", token),
      revoke: (shareId: string, token: string) => del<void>(`/shares/${shareId}`, token),
      view: (shareId: string) => post<ViewShareResponse>(`/shares/${shareId}/view`, {}),
    },
    sync: {
      pull: (req: SyncRequest, token: string) => post<SyncResponse>("/sync", req, token),
      push: (events: unknown[], token: string) => post<{ accepted: number }>("/sync/events", events, token),
    },
    orgs: {
      list: (token: string) => get<OrgSummary[]>("/organizations", token),
      get: (orgId: string, token: string) => get<OrgDetails>(`/organizations/${orgId}`, token),
      invites: (token: string) => get<PendingInvite[]>("/organizations/invites", token),
      rewrap: (orgId: string, req: RewrapRequest, token: string) =>
        put<void>(`/organizations/${orgId}/wraps`, req, token),
      items: (orgId: string, token: string) => get<EncryptedVaultItem[]>(`/organizations/${orgId}/items`, token),
      rotate: (orgId: string, req: RotateKeyRequest, token: string) =>
        post<void>(`/organizations/${orgId}/rotate`, req, token),
      create: (req: CreateOrgRequest, token: string) => post<OrgSummary>("/organizations", req, token),
      invite: (orgId: string, req: InviteMemberRequest, token: string) =>
        post<void>(`/organizations/${orgId}/members`, req, token),
      accept: (orgId: string, token: string) =>
        post<void>(`/organizations/${orgId}/accept`, {}, token),
      getPublicKey: (emailHash: string, token: string) =>
        get<PublicKeyResponse>(`/organizations/public-key/${emailHash}`, token),
    },
    keys: {
      me: (token: string) => get<PublicKeyResponse>("/keys/me", token),
      setIdentity: (req: SetIdentityRequest, token: string) => put<void>("/keys/identity", req, token),
      vaultFormat: (token: string) => get<VaultFormatMarker>("/keys/vault-format", token),
      setVaultFormat: (req: { marker: string }, token: string) => put<void>("/keys/vault-format", req, token),
    },
    billing: {
      status: (token: string) => get<BillingStatus>("/billing/status", token),
      checkout: (req: CreateCheckoutRequest, token: string) =>
        post<CheckoutSessionResponse>("/billing/checkout", req, token),
      portal: (req: CreatePortalRequest, token: string) =>
        post<PortalSessionResponse>("/billing/portal", req, token),
    },
  };
}

export type ApiClient = ReturnType<typeof createApiClient>;
