import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { I18nProvider } from "../i18n";
import { PublicConfigProvider } from "../public-config";
import { RouterProvider } from "../router";
import { LoginPage } from "./LoginPage";

const verifiedConfig = {
  environment: "production",
  public_registration_enabled: true,
  registration_mode: "verified",
  registration_identity_kinds: ["email", "phone"],
  identity_verification_available: true,
};

const directConfig = {
  environment: "internal_beta",
  public_registration_enabled: true,
  registration_mode: "direct",
  registration_identity_kinds: ["email"],
  identity_verification_available: false,
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderLogin() {
  window.history.replaceState(null, "", "/login");
  return render(
    <I18nProvider>
      <PublicConfigProvider>
        <RouterProvider>
          <LoginPage />
        </RouterProvider>
      </PublicConfigProvider>
    </I18nProvider>,
  );
}

test("submits credentials only in the JSON body and stores the CSRF token", async () => {
  const fetchMock = vi
    .spyOn(window, "fetch")
    .mockImplementation(async (input) => {
      if (String(input) === "/api/v1/public/config") {
        return jsonResponse(verifiedConfig);
      }
      if (String(input) === "/api/v1/browser/login") {
        return jsonResponse({
          user_id: "10000000-0000-4000-8000-000000000001",
          personal_space_id: "20000000-0000-4000-8000-000000000002",
          nickname: "Alice",
          csrf_token: "a".repeat(43),
        });
      }
      throw new Error(`unexpected request: ${String(input)}`);
    });
  renderLogin();

  fireEvent.change(screen.getByLabelText("邮箱或手机号"), {
    target: { value: "alice@example.com" },
  });
  fireEvent.change(screen.getByLabelText("密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.click(screen.getByRole("button", { name: "登录" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  const loginCall = fetchMock.mock.calls.find(
    ([input]) => String(input) === "/api/v1/browser/login",
  );
  const [url, init] = loginCall ?? [];
  expect(url).toBe("/api/v1/browser/login");
  expect(JSON.parse(String(init?.body))).toEqual({
    identity: "alice@example.com",
    password: "correct horse battery",
  });
  expect(window.location.href).not.toContain("alice@example.com");
  expect(window.location.href).not.toContain("correct%20horse");
  expect(window.sessionStorage.getItem("agentera.csrf_token")).toBe(
    "a".repeat(43),
  );
});

test("offers registration, password recovery, and deletion recovery without embedding identity values in links", async () => {
  vi.spyOn(window, "fetch").mockResolvedValue(jsonResponse(verifiedConfig));
  renderLogin();

  expect(await screen.findByRole("link", { name: "创建账户" })).toHaveAttribute(
    "href",
    "/register",
  );
  expect(await screen.findByRole("link", { name: "忘记密码" })).toHaveAttribute(
    "href",
    "/forgot-password",
  );
  expect(
    await screen.findByRole("link", { name: "恢复待注销账户" }),
  ).toHaveAttribute("href", "/delete-account?mode=recover");
});

test("direct internal beta hides all verification-dependent recovery entry points", async () => {
  vi.spyOn(window, "fetch").mockResolvedValue(jsonResponse(directConfig));
  renderLogin();

  expect(
    await screen.findByText(/暂不支持找回密码、身份绑定或注销恢复/),
  ).toBeVisible();
  expect(screen.getByRole("link", { name: "创建账户" })).toHaveAttribute(
    "href",
    "/register",
  );
  expect(
    screen.queryByRole("link", { name: "忘记密码" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("link", { name: "恢复待注销账户" }),
  ).not.toBeInTheDocument();
});
