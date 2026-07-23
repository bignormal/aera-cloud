import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { I18nProvider } from "../i18n";
import { PublicConfigProvider } from "../public-config";
import { RouterProvider } from "../router";
import { RegisterPage } from "./RegisterPage";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

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

function renderRegistration() {
  return render(
    <I18nProvider>
      <PublicConfigProvider>
        <RouterProvider>
          <RegisterPage />
        </RouterProvider>
      </PublicConfigProvider>
    </I18nProvider>,
  );
}

test("completes verified email registration using current legal versions", async () => {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  vi.spyOn(window, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === "/api/v1/public/config") {
      return jsonResponse(verifiedConfig);
    }
    if (url === "/api/v1/legal/current") {
      return jsonResponse({
        terms_version: "2026-07",
        privacy_version: "2026-07",
      });
    }
    const body = JSON.parse(String(init?.body ?? "{}"));
    calls.push({ url, body });
    if (url.endsWith("/verify")) {
      return jsonResponse({
        status: "verified",
        receipt: "verified-receipt",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      });
    }
    if (url.endsWith("/register")) {
      return jsonResponse(
        {
          user_id: crypto.randomUUID(),
          personal_space_id: crypto.randomUUID(),
        },
        201,
      );
    }
    return jsonResponse({ status: "accepted" }, 202);
  });
  renderRegistration();

  fireEvent.change(await screen.findByRole("textbox", { name: "邮箱" }), {
    target: { value: "alice@example.com" },
  });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));
  await screen.findByText("验证码已发送");
  fireEvent.change(screen.getByLabelText("6 位验证码"), {
    target: { value: "123456" },
  });
  fireEvent.click(screen.getByRole("button", { name: "验证" }));
  await screen.findByText("身份验证完成");
  fireEvent.change(screen.getByLabelText("设置密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.change(screen.getByLabelText("确认密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.click(screen.getByLabelText("我已阅读并同意服务条款和隐私政策"));
  fireEvent.click(screen.getByRole("button", { name: "创建 AgentEra 账户" }));

  await waitFor(() =>
    expect(calls.some((call) => call.url.endsWith("/register"))).toBe(true),
  );
  const registration = calls.find((call) => call.url.endsWith("/register"));
  expect(registration?.body).toMatchObject({
    kind: "email",
    verification_receipt: "verified-receipt",
    terms_version: "2026-07",
    privacy_version: "2026-07",
  });
});

test("supports mainland phone registration as an explicit identity choice", async () => {
  const fetchMock = vi
    .spyOn(window, "fetch")
    .mockImplementation(async (input, init) => {
      const url = String(input);
      if (url === "/api/v1/public/config") {
        return jsonResponse(verifiedConfig);
      }
      if (url === "/api/v1/legal/current") {
        return jsonResponse({
          terms_version: "2026-07",
          privacy_version: "2026-07",
        });
      }
      return jsonResponse({ status: "accepted" }, 202);
    });
  renderRegistration();

  fireEvent.click(await screen.findByRole("radio", { name: "中国大陆手机号" }));
  fireEvent.change(screen.getByRole("textbox", { name: "中国大陆手机号" }), {
    target: { value: "13800138000" },
  });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(3));
  const verificationCall = fetchMock.mock.calls.find(
    ([input]) => String(input) === "/api/v1/verification/challenges",
  );
  const init = verificationCall?.[1];
  expect(JSON.parse(String(init?.body))).toMatchObject({
    kind: "phone",
    destination: "13800138000",
    purpose: "registration",
  });
});

test("direct internal beta waits for both capability and legal configuration before rendering", async () => {
  let resolveConfig!: (response: Response) => void;
  let resolveLegal!: (response: Response) => void;
  vi.spyOn(window, "fetch").mockImplementation((input) => {
    if (String(input) === "/api/v1/public/config") {
      return new Promise((resolve) => {
        resolveConfig = resolve;
      });
    }
    if (String(input) === "/api/v1/legal/current") {
      return new Promise((resolve) => {
        resolveLegal = resolve;
      });
    }
    throw new Error(`unexpected request: ${String(input)}`);
  });

  renderRegistration();

  expect(
    screen.queryByRole("button", { name: "创建 AgentEra 账户" }),
  ).not.toBeInTheDocument();
  resolveLegal(
    jsonResponse({ terms_version: "2026-07", privacy_version: "2026-07" }),
  );
  await Promise.resolve();
  expect(
    screen.queryByRole("button", { name: "创建 AgentEra 账户" }),
  ).not.toBeInTheDocument();

  resolveConfig(jsonResponse(directConfig));
  expect(
    await screen.findByRole("button", { name: "创建 AgentEra 账户" }),
  ).toBeVisible();
});

test("direct internal beta submits an unverified normalized email identifier without verification controls", async () => {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  vi.spyOn(window, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === "/api/v1/public/config") {
      return jsonResponse(directConfig);
    }
    if (url === "/api/v1/legal/current") {
      return jsonResponse({
        terms_version: "2026-07",
        privacy_version: "2026-07",
      });
    }
    if (url === "/api/v1/accounts/register") {
      calls.push({ url, body: JSON.parse(String(init?.body ?? "{}")) });
      return jsonResponse(
        {
          user_id: crypto.randomUUID(),
          personal_space_id: crypto.randomUUID(),
        },
        201,
      );
    }
    throw new Error(`unexpected request: ${url}`);
  });

  renderRegistration();

  const identity = await screen.findByRole("textbox", {
    name: "内测登录邮箱（未验证）",
  });
  expect(
    screen.getByText(/暂不支持找回密码、身份绑定或注销恢复/),
  ).toBeVisible();
  expect(
    screen.queryByRole("radio", { name: "中国大陆手机号" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "发送验证码" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByLabelText("6 位验证码")).not.toBeInTheDocument();

  fireEvent.change(identity, { target: { value: "  Alice@Example.COM  " } });
  fireEvent.change(screen.getByLabelText("设置密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.change(screen.getByLabelText("确认密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.click(screen.getByLabelText("我已阅读并同意服务条款和隐私政策"));
  fireEvent.click(screen.getByRole("button", { name: "创建 AgentEra 账户" }));

  await waitFor(() => expect(calls).toHaveLength(1));
  expect(calls[0].body).toEqual({
    kind: "email",
    identity: "alice@example.com",
    password: "correct horse battery",
    nickname: "",
    terms_version: "2026-07",
    privacy_version: "2026-07",
  });
  expect(calls[0].body).not.toHaveProperty("verification_receipt");
});

test("direct internal beta rejects an invalid email before account creation", async () => {
  let registrationCalls = 0;
  vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    if (url === "/api/v1/public/config") {
      return jsonResponse(directConfig);
    }
    if (url === "/api/v1/legal/current") {
      return jsonResponse({
        terms_version: "2026-07",
        privacy_version: "2026-07",
      });
    }
    if (url === "/api/v1/accounts/register") {
      registrationCalls += 1;
      return jsonResponse({}, 201);
    }
    throw new Error(`unexpected request: ${url}`);
  });

  renderRegistration();

  fireEvent.change(
    await screen.findByRole("textbox", {
      name: "内测登录邮箱（未验证）",
    }),
    { target: { value: "not-an-email" } },
  );
  fireEvent.change(screen.getByLabelText("设置密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.change(screen.getByLabelText("确认密码"), {
    target: { value: "correct horse battery" },
  });
  fireEvent.click(screen.getByLabelText("我已阅读并同意服务条款和隐私政策"));
  fireEvent.click(screen.getByRole("button", { name: "创建 AgentEra 账户" }));

  expect(await screen.findByText("请输入有效的内测登录邮箱。")).toBeVisible();
  expect(registrationCalls).toBe(0);
});
