import { render, screen } from "@testing-library/react";
import { I18nProvider } from "../i18n";
import { PublicConfigProvider } from "../public-config";
import { RouterProvider } from "../router";
import { AccountPage } from "./AccountPage";
import { ForgotPasswordPage } from "./ForgotPasswordPage";

const directConfig = {
  environment: "internal_beta",
  public_registration_enabled: true,
  registration_mode: "direct",
  registration_identity_kinds: ["email"],
  identity_verification_available: false,
};

const phoneOnlyVerifiedConfig = {
  environment: "internal_beta",
  public_registration_enabled: true,
  registration_mode: "verified",
  registration_identity_kinds: ["phone"],
  identity_verification_available: true,
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderPage(page: React.ReactNode) {
  return render(
    <I18nProvider>
      <PublicConfigProvider>
        <RouterProvider>{page}</RouterProvider>
      </PublicConfigProvider>
    </I18nProvider>,
  );
}

test("direct internal beta blocks password reset before any verification request", async () => {
  const fetchMock = vi
    .spyOn(window, "fetch")
    .mockResolvedValue(jsonResponse(directConfig));

  renderPage(<ForgotPasswordPage />);

  expect(
    await screen.findByRole("heading", { name: "当前内测暂不支持此功能" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "发送验证码" }),
  ).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledOnce();
});

test("direct internal beta labels the login identifier unverified and hides identity mutation and deletion controls", async () => {
  vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/v1/public/config") {
      return jsonResponse(directConfig);
    }
    if (String(input) === "/api/v1/accounts/me") {
      return jsonResponse({
        user_id: "10000000-0000-4000-8000-000000000001",
        personal_space_id: "20000000-0000-4000-8000-000000000002",
        nickname: "Alice",
        status: "active",
        identity_kinds: ["email"],
        owned_workspace_count: 0,
      });
    }
    throw new Error(`unexpected request: ${String(input)}`);
  });

  renderPage(<AccountPage />);

  expect(await screen.findByText("未验证")).toBeVisible();
  expect(
    screen.queryByRole("heading", { name: "绑定另一登录方式" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("link", { name: "注销 AgentEra 账户" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/暂不支持找回密码、身份绑定或注销恢复/),
  ).toBeVisible();
});

test("phone-only verified deployment does not offer an unavailable email identity", async () => {
  vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/v1/public/config") {
      return jsonResponse(phoneOnlyVerifiedConfig);
    }
    if (String(input) === "/api/v1/accounts/me") {
      return jsonResponse({
        user_id: "10000000-0000-4000-8000-000000000001",
        personal_space_id: "20000000-0000-4000-8000-000000000002",
        nickname: "Alice",
        status: "active",
        identity_kinds: ["phone"],
        owned_workspace_count: 0,
      });
    }
    throw new Error(`unexpected request: ${String(input)}`);
  });

  renderPage(<AccountPage />);

  expect(await screen.findByText("手机号")).toBeVisible();
  expect(
    screen.queryByRole("heading", { name: "绑定另一登录方式" }),
  ).not.toBeInTheDocument();
});
