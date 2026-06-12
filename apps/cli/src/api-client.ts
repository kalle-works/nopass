import type {
  DeviceInfo,
  EncryptedVaultItem,
  RegisterDeviceRequest,
  SrpInitRequest,
  SrpInitResponse,
  SrpVerifyRequest,
  SrpVerifyResponse,
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

async function request<T>(
  baseUrl: string,
  path: string,
  options: RequestInit & { token?: string },
): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options.token) headers["Authorization"] = `Bearer ${options.token}`;

  const res = await fetch(`${baseUrl}/v1${path}`, { ...options, headers });

  if (!res.ok) {
    const body = (await res.json().catch(() => ({ error: res.statusText }))) as { error: string };
    throw new ApiError(body.error, res.status);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export function createApiClient(baseUrl: string) {
  const get = <T>(path: string, token?: string) =>
    request<T>(baseUrl, path, { method: "GET", ...(token ? { token } : {}) });

  const post = <T>(path: string, body: unknown, token?: string) =>
    request<T>(baseUrl, path, { method: "POST", body: JSON.stringify(body), ...(token ? { token } : {}) });

  const del = <T>(path: string, token?: string) =>
    request<T>(baseUrl, path, { method: "DELETE", ...(token ? { token } : {}) });

  return {
    auth: {
      srpInit: (req: SrpInitRequest) => post<SrpInitResponse>("/auth/srp/init", req),
      srpVerify: (req: SrpVerifyRequest) => post<SrpVerifyResponse>("/auth/srp/verify", req),
      logout: (token: string) => post<void>("/auth/logout", {}, token),
    },
    devices: {
      list: (token: string) => get<DeviceInfo[]>("/devices", token),
      register: (req: RegisterDeviceRequest, token: string) =>
        post<{ deviceId: string }>("/devices", req, token),
      remove: (deviceId: string, token: string) => del<void>(`/devices/${deviceId}`, token),
    },
    vault: {
      items: (vaultId: string, token: string) =>
        get<EncryptedVaultItem[]>(`/vaults/${vaultId}/items`, token),
    },
  };
}
