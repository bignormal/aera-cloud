import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { I18nProvider } from "../i18n";
import { RouterProvider } from "../router";
import { LoginPage } from "./LoginPage";

function renderLogin() {
  window.history.replaceState(null, "", "/login");
  return render(
    <I18nProvider>
      <RouterProvider>
        <LoginPage />
      </RouterProvider>
    </I18nProvider>,
  );
}

test("submits credentials only in the JSON body and stores the CSRF token", async () => {
  const fetchMock = vi.spyOn(window, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({
        user_id: "10000000-0000-4000-8000-000000000001",
        personal_space_id: "20000000-0000-4000-8000-000000000002",
        nickname: "Alice",
        csrf_token: "a".repeat(43),
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  );
  renderLogin();

  fireEvent.change(screen.getByLabelText("邮箱或手机号"), { target: { value: "alice@example.com" } });
  fireEvent.change(screen.getByLabelText("密码"), { target: { value: "correct horse battery" } });
  fireEvent.click(screen.getByRole("button", { name: "登录" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  const [url, init] = fetchMock.mock.calls[0];
  expect(url).toBe("/api/v1/browser/login");
  expect(JSON.parse(String(init?.body))).toEqual({
    identity: "alice@example.com",
    password: "correct horse battery",
  });
  expect(window.location.href).not.toContain("alice@example.com");
  expect(window.location.href).not.toContain("correct%20horse");
  expect(window.sessionStorage.getItem("agentera.csrf_token")).toBe("a".repeat(43));
});

test("offers registration, password recovery, and deletion recovery without embedding identity values in links", () => {
  renderLogin();

  expect(screen.getByRole("link", { name: "创建账户" })).toHaveAttribute("href", "/register");
  expect(screen.getByRole("link", { name: "忘记密码" })).toHaveAttribute("href", "/forgot-password");
  expect(screen.getByRole("link", { name: "恢复待注销账户" })).toHaveAttribute("href", "/delete-account?mode=recover");
});
