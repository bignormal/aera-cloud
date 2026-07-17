const csrfStorageKey = "agentera.csrf_token";

let inMemoryToken = "";

export function setCSRFToken(token: string): void {
  inMemoryToken = token;
  try {
    if (token) {
      window.sessionStorage.setItem(csrfStorageKey, token);
    } else {
      window.sessionStorage.removeItem(csrfStorageKey);
    }
  } catch {
    // In-memory storage remains available when browser storage is disabled.
  }
}

export function getCSRFToken(): string {
  if (inMemoryToken) {
    return inMemoryToken;
  }
  try {
    inMemoryToken = window.sessionStorage.getItem(csrfStorageKey) ?? "";
  } catch {
    inMemoryToken = "";
  }
  return inMemoryToken;
}

export function clearCSRFToken(): void {
  setCSRFToken("");
}
