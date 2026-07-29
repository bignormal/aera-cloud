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

function renderLogin(search = "") {
  window.history.replaceState(null, "", `/login${search}`);
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
  expect(window.localStorage.getItem("agentera.csrf_token")).toBe(
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

test("preserves a safe OAuth continuation when opening registration", async () => {
  vi.spyOn(window, "fetch").mockResolvedValue(jsonResponse(verifiedConfig));
  renderLogin(
    "?next=%2Fauthorize%3Frequest_id%3D019f8ccf-effa-71a1-bdde-d4c935ee1670",
  );

  expect(
    await screen.findByRole("link", { name: "创建账户" }),
  ).toHaveAttribute(
    "href",
    "/register?next=%2Fauthorize%3Frequest_id%3D019f8ccf-effa-71a1-bdde-d4c935ee1670",
  );
});

test("does not carry an external OAuth continuation into registration", async () => {
  vi.spyOn(window, "fetch").mockResolvedValue(jsonResponse(verifiedConfig));
  renderLogin("?next=https%3A%2F%2Fevil.example%2Fsteal");

  expect(
    await screen.findByRole("link", { name: "创建账户" }),
  ).toHaveAttribute("href", "/register");
});

test("signs in with a phone verification code through the login-purpose receipt", async () => {
  const fetchMock = vi
    .spyOn(window, "fetch")
    .mockImplementation(async (input) => {
      if (String(input) === "/api/v1/public/config") {
        return jsonResponse(verifiedConfig);
      }
      if (String(input) === "/api/v1/verification/challenges") {
        return jsonResponse({ status: "accepted" }, 202);
      }
      if (String(input) === "/api/v1/verification/challenges/verify") {
        return jsonResponse({
          status: "verified",
          receipt: "opaque-login-receipt",
          expires_at: "2026-07-24T12:10:00Z",
        });
      }
      if (String(input) === "/api/v1/browser/login/code") {
        return jsonResponse({
          user_id: "10000000-0000-4000-8000-000000000001",
          personal_space_id: "20000000-0000-4000-8000-000000000002",
          nickname: "Alice",
          csrf_token: "b".repeat(43),
        });
      }
      throw new Error(`unexpected request: ${String(input)}`);
    });
  renderLogin();

  fireEvent.click(await screen.findByLabelText("验证码登录"));
  fireEvent.change(screen.getByLabelText("中国大陆手机号"), {
    target: { value: "+8613800138000" },
  });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));
  await screen.findByText("验证码已发送");

  fireEvent.change(screen.getByLabelText("6 位验证码"), {
    target: { value: "123456" },
  });
  fireEvent.click(screen.getByRole("button", { name: "验证码登录" }));

  await waitFor(() =>
    expect(window.localStorage.getItem("agentera.csrf_token")).toBe(
      "b".repeat(43),
    ),
  );
  const challengeCall = fetchMock.mock.calls.find(
    ([input]) => String(input) === "/api/v1/verification/challenges",
  );
  expect(JSON.parse(String(challengeCall?.[1]?.body))).toMatchObject({
    kind: "phone",
    destination: "+8613800138000",
    purpose: "login",
  });
  const codeLoginCall = fetchMock.mock.calls.find(
    ([input]) => String(input) === "/api/v1/browser/login/code",
  );
  expect(JSON.parse(String(codeLoginCall?.[1]?.body))).toEqual({
    verification_receipt: "opaque-login-receipt",
  });
});

test("shows the unified one-minute prompt when login SMS is cooling down", async () => {
  vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/v1/public/config") {
      return jsonResponse(verifiedConfig);
    }
    if (String(input) === "/api/v1/verification/challenges") {
      return jsonResponse({ error: "resend_too_soon" }, 429);
    }
    throw new Error(`unexpected request: ${String(input)}`);
  });
  renderLogin();

  fireEvent.click(await screen.findByLabelText("验证码登录"));
  fireEvent.change(screen.getByLabelText("中国大陆手机号"), {
    target: { value: "+8613800138000" },
  });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));

  expect(
    await screen.findByText("请求过于频繁，请下一分钟后重试"),
  ).toBeVisible();
});

test("shows a verification-code error without referring to the password", async () => {
  vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/v1/public/config") {
      return jsonResponse(verifiedConfig);
    }
    if (String(input) === "/api/v1/verification/challenges") {
      return jsonResponse({ status: "accepted" }, 202);
    }
    if (String(input) === "/api/v1/verification/challenges/verify") {
      return jsonResponse({ error: { code: "invalid_or_expired_code" } }, 400);
    }
    throw new Error(`unexpected request: ${String(input)}`);
  });
  renderLogin();

  fireEvent.click(await screen.findByLabelText("验证码登录"));
  fireEvent.change(screen.getByLabelText("中国大陆手机号"), {
    target: { value: "+8613800138000" },
  });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));
  await screen.findByText("验证码已发送");
  fireEvent.change(screen.getByLabelText("6 位验证码"), {
    target: { value: "000000" },
  });
  fireEvent.click(screen.getByRole("button", { name: "验证码登录" }));

  expect(
    await screen.findByText("验证码无效或已过期，请重新获取。"),
  ).toBeVisible();
  expect(screen.queryByText(/账户和密码/)).not.toBeInTheDocument();
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
