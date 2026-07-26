const csrfStorageKey = "agentera.csrf_token";

let inMemoryToken = "";

export function setCSRFToken(token: string): void {
  inMemoryToken = token;
  try {
    if (token) {
      window.localStorage.setItem(csrfStorageKey, token);
    } else {
      window.localStorage.removeItem(csrfStorageKey);
    }
  } catch {
    // In-memory storage remains available when localStorage is disabled.
  }
  try {
    // Legacy per-tab storage from earlier releases must be cleared even when
    // localStorage is unavailable.
    window.sessionStorage.removeItem(csrfStorageKey);
  } catch {
    // In-memory storage remains available when sessionStorage is disabled.
  }
}

export function getCSRFToken(): string {
  if (inMemoryToken) {
    return inMemoryToken;
  }
  try {
    // localStorage is shared across tabs, so an authorize page opened in a
    // new tab can reuse the token issued at login. Fall back to the legacy
    // sessionStorage slot for sessions started before this change.
    inMemoryToken =
      window.localStorage.getItem(csrfStorageKey) ??
      window.sessionStorage.getItem(csrfStorageKey) ??
      "";
  } catch {
    inMemoryToken = "";
  }
  return inMemoryToken;
}

export function clearCSRFToken(): void {
  setCSRFToken("");
}
