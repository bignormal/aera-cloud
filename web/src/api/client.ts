import { getCSRFToken } from "../auth/csrf";

export type IdentityKind = "email" | "phone";
export type VerificationPurpose =
  | "registration"
  | "password_reset"
  | "bind_identity"
  | "account_deletion"
  | "deletion_recovery";

export interface AccountProfile {
  user_id: string;
  personal_space_id: string;
  nickname?: string;
  status: "active";
  identity_kinds: IdentityKind[];
}

export interface BrowserLoginResponse {
  user_id: string;
  personal_space_id: string;
  nickname?: string;
  csrf_token: string;
}

export interface LegalDocuments {
  terms_version: string;
  privacy_version: string;
}

export interface VerificationReceipt {
  status: "verified";
  receipt: string;
  expires_at: string;
}

export interface Device {
  device_id: string;
  display_name: string;
  platform: "darwin" | "windows" | "linux";
  app_version: string;
  status: "active" | "inactive" | "revoked";
  last_seen_at: string;
  current: boolean;
}

interface RequestOptions {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  csrf?: boolean;
  headers?: Record<string, string>;
}

export class APIError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestID?: string;

  constructor(status: number, code: string, requestID?: string) {
    super(code);
    this.name = "APIError";
    this.status = status;
    this.code = code;
    this.requestID = requestID;
  }
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  if (!path.startsWith("/") || path.startsWith("//")) {
    throw new APIError(0, "invalid_request");
  }
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...options.headers,
  };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (options.csrf) {
    const token = getCSRFToken();
    if (!token) {
      throw new APIError(401, "csrf_missing");
    }
    headers["X-CSRF-Token"] = token;
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method: options.method ?? "GET",
      credentials: "same-origin",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new APIError(0, "network_error");
  }
  const payload = await parseJSON(response);
  if (!response.ok) {
    const nested = isRecord(payload) && isRecord(payload.error) ? payload.error : undefined;
    const directCode = isRecord(payload) && typeof payload.error === "string" ? payload.error : undefined;
    const code = (nested && typeof nested.code === "string" ? nested.code : directCode) ?? "service_unavailable";
    const requestID = nested && typeof nested.request_id === "string" ? nested.request_id : undefined;
    throw new APIError(response.status, code, requestID);
  }
  return payload as T;
}

async function parseJSON(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return undefined;
  }
  const contentType = response.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return undefined;
  }
  try {
    return await response.json();
  } catch {
    throw new APIError(response.status, "invalid_response");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function opaqueBrowserID(): string {
  const existing = readLocalStorage("agentera.web_installation_id");
  if (existing) {
    return existing;
  }
  let generated = "";
  if (typeof crypto.randomUUID === "function") {
    generated = crypto.randomUUID();
  } else {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    generated = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  }
  try {
    window.localStorage.setItem("agentera.web_installation_id", generated);
  } catch {
    // The request still has a per-page abuse-control identifier.
  }
  return generated;
}

function readLocalStorage(key: string): string {
  try {
    return window.localStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

export function getProfile(): Promise<AccountProfile> {
  return request<AccountProfile>("/api/v1/accounts/me");
}

export function getLegalDocuments(): Promise<LegalDocuments> {
  return request<LegalDocuments>("/api/v1/legal/current");
}

export function login(identity: string, password: string): Promise<BrowserLoginResponse> {
  return request<BrowserLoginResponse>("/api/v1/browser/login", {
    method: "POST",
    body: { identity, password },
  });
}

export function logout(): Promise<void> {
  return request<void>("/api/v1/browser/logout", { method: "POST", csrf: true });
}

export function sendVerification(
  kind: IdentityKind,
  destination: string,
  purpose: VerificationPurpose,
  captchaToken = "",
): Promise<{ status: string }> {
  return request<{ status: string }>("/api/v1/verification/challenges", {
    method: "POST",
    headers: {
      "Idempotency-Key": crypto.randomUUID(),
      "X-AgentEra-Installation-ID": opaqueBrowserID(),
    },
    body: { kind, destination, purpose, captcha_token: captchaToken },
  });
}

export function verifyIdentity(
  kind: IdentityKind,
  destination: string,
  purpose: VerificationPurpose,
  code: string,
): Promise<VerificationReceipt> {
  return request<VerificationReceipt>("/api/v1/verification/challenges/verify", {
    method: "POST",
    body: { kind, destination, purpose, code },
  });
}

export function registerAccount(input: {
  kind: IdentityKind;
  verification_receipt: string;
  password: string;
  nickname: string;
  terms_version: string;
  privacy_version: string;
}): Promise<{ user_id: string; personal_space_id: string }> {
  return request("/api/v1/accounts/register", { method: "POST", body: input });
}

export function resetPassword(verificationReceipt: string, newPassword: string): Promise<void> {
  return request<void>("/api/v1/accounts/password/reset", {
    method: "POST",
    body: { verification_receipt: verificationReceipt, new_password: newPassword },
  });
}

export function bindIdentity(currentPassword: string, verificationReceipt: string): Promise<void> {
  return request<void>("/api/v1/accounts/identities/bind", {
    method: "POST",
    csrf: true,
    body: { current_password: currentPassword, verification_receipt: verificationReceipt },
  });
}

export function removeIdentity(kind: IdentityKind, currentPassword: string): Promise<void> {
  return request<void>(`/api/v1/accounts/identities/${kind}`, {
    method: "DELETE",
    csrf: true,
    body: { current_password: currentPassword },
  });
}

export async function listDevices(): Promise<Device[]> {
  const result = await request<{ devices: Device[] }>("/api/v1/devices");
  return result.devices;
}

export function revokeDevice(deviceID: string): Promise<void> {
  return request<void>(`/api/v1/devices/${encodeURIComponent(deviceID)}`, {
    method: "DELETE",
    csrf: true,
  });
}

export function requestDeletion(currentPassword: string, verificationReceipt: string): Promise<void> {
  return request<void>("/api/v1/accounts/deletion", {
    method: "POST",
    csrf: true,
    body: { current_password: currentPassword, verification_receipt: verificationReceipt },
  });
}

export function recoverDeletion(identity: string, password: string, verificationReceipt: string): Promise<void> {
  return request<void>("/api/v1/accounts/deletion/recover", {
    method: "POST",
    body: { identity, password, verification_receipt: verificationReceipt },
  });
}

export function approveAuthorization(requestID: string): Promise<{ redirect_uri: string }> {
  return request<{ redirect_uri: string }>("/api/v1/oauth/authorize/approve", {
    method: "POST",
    csrf: true,
    body: { request_id: requestID },
  });
}
