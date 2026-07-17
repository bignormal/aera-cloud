import "@testing-library/jest-dom/vitest";

afterEach(() => {
  window.history.replaceState(null, "", "/");
  window.sessionStorage.clear();
  window.localStorage.clear();
  vi.restoreAllMocks();
});
