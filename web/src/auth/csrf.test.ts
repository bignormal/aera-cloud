import { clearCSRFToken, getCSRFToken, setCSRFToken } from "./csrf";

const storageKey = "agentera.csrf_token";

beforeEach(() => {
  // The module caches the token in memory; reset it between tests.
  clearCSRFToken();
});

test("stores the token in localStorage so a new tab can approve authorizations", () => {
  setCSRFToken("t".repeat(43));

  expect(window.localStorage.getItem(storageKey)).toBe("t".repeat(43));
  expect(window.sessionStorage.getItem(storageKey)).toBeNull();

  // Simulate a fresh tab: only browser storage survives, not module memory.
  clearModuleMemory();
  expect(getCSRFToken()).toBe("t".repeat(43));
});

test("falls back to the legacy sessionStorage slot from earlier releases", () => {
  window.sessionStorage.setItem(storageKey, "legacy-token");

  expect(getCSRFToken()).toBe("legacy-token");
});

test("clearing removes the token from every storage slot", () => {
  setCSRFToken("t".repeat(43));
  window.sessionStorage.setItem(storageKey, "legacy-token");

  clearCSRFToken();

  expect(getCSRFToken()).toBe("");
  expect(window.localStorage.getItem(storageKey)).toBeNull();
  expect(window.sessionStorage.getItem(storageKey)).toBeNull();
});

test("clears legacy session storage even when localStorage rejects the write", () => {
  window.sessionStorage.setItem(storageKey, "legacy-token");
  const originalSetItem = Storage.prototype.setItem;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(
    function (this: Storage, key, value) {
      if (this === window.localStorage) {
        throw new Error("localStorage disabled");
      }
      return originalSetItem.call(this, key, value);
    },
  );

  setCSRFToken("t".repeat(43));

  expect(window.sessionStorage.getItem(storageKey)).toBeNull();
  expect(getCSRFToken()).toBe("t".repeat(43));
});

function clearModuleMemory() {
  // clearCSRFToken resets the in-memory cache but also wipes storage, so
  // stash the persisted value and restore it afterwards.
  const persisted = window.localStorage.getItem(storageKey);
  clearCSRFToken();
  if (persisted !== null) {
    window.localStorage.setItem(storageKey, persisted);
  }
}
