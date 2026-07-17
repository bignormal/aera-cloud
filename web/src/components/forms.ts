import { APIError, type IdentityKind } from "../api/client";

export function inferIdentityKind(value: string): IdentityKind {
  return value.trim().includes("@") ? "email" : "phone";
}

export function errorKey(error: unknown): "loginError" | "networkError" | "serviceError" {
  if (error instanceof APIError && error.code === "network_error") {
    return "networkError";
  }
  if (error instanceof APIError && (error.code === "invalid_credentials" || error.code === "account_not_found")) {
    return "loginError";
  }
  return "serviceError";
}

export function validPassword(value: string): boolean {
  return value.length >= 10 && value.length <= 128;
}
