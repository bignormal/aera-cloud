import { getProfile } from "./client";
import { clearCSRFToken, getCSRFToken, setCSRFToken } from "../auth/csrf";

test("clears the persisted CSRF token when the browser session is revoked", async () => {
  setCSRFToken("t".repeat(43));
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: "session_revoked", request_id: "request-1" },
        }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      ),
    ),
  );

  await expect(getProfile()).rejects.toMatchObject({
    status: 401,
    code: "session_revoked",
  });
  expect(getCSRFToken()).toBe("");
});

test("keeps the current CSRF token when a login attempt has invalid credentials", async () => {
  const token = "t".repeat(43);
  setCSRFToken(token);
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: { code: "invalid_credentials", request_id: "request-2" },
        }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      ),
    ),
  );

  await expect(getProfile()).rejects.toMatchObject({
    status: 401,
    code: "invalid_credentials",
  });
  expect(getCSRFToken()).toBe(token);
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearCSRFToken();
});
