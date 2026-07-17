import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { setCSRFToken } from "../auth/csrf";
import { I18nProvider } from "../i18n";
import { RouterProvider } from "../router";
import { AuthorizePage } from "./AuthorizePage";

test("approves only the request id and never renders returned credentials", async () => {
  const requestID = "10000000-0000-4000-8000-000000000001";
  window.history.replaceState(null, "", `/authorize?request_id=${requestID}`);
  setCSRFToken("c".repeat(43));
  const fetchMock = vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/v1/accounts/me") {
      return new Response(
        JSON.stringify({
          user_id: crypto.randomUUID(), personal_space_id: crypto.randomUUID(), nickname: "Alice",
          status: "active", identity_kinds: ["email"],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response(
      JSON.stringify({ redirect_uri: "http://127.0.0.1:43123/agentera/oauth/callback?code=opaque&state=opaque" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  });
  const redirect = vi.fn();
  render(
    <I18nProvider>
      <RouterProvider>
        <AuthorizePage redirectToDesktop={redirect} />
      </RouterProvider>
    </I18nProvider>,
  );

  fireEvent.click(await screen.findByRole("button", { name: "允许并返回 AgentEra Studio" }));

  await waitFor(() => expect(redirect).toHaveBeenCalledOnce());
  const [, init] = fetchMock.mock.calls.find(([url]) => String(url).endsWith("/approve"))!;
  expect(JSON.parse(String(init?.body))).toEqual({ request_id: requestID });
  expect(init?.headers).toMatchObject({ "X-CSRF-Token": "c".repeat(43) });
  expect(document.body.textContent).not.toContain("opaque&state");
  expect(document.body.textContent).not.toContain("access_token");
});
