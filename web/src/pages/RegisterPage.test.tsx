import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { I18nProvider } from "../i18n";
import { RouterProvider } from "../router";
import { RegisterPage } from "./RegisterPage";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

test("completes verified email registration using current legal versions", async () => {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  vi.spyOn(window, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === "/api/v1/legal/current") {
      return jsonResponse({ terms_version: "2026-07", privacy_version: "2026-07" });
    }
    const body = JSON.parse(String(init?.body ?? "{}"));
    calls.push({ url, body });
    if (url.endsWith("/verify")) {
      return jsonResponse({ status: "verified", receipt: "verified-receipt", expires_at: new Date(Date.now() + 60_000).toISOString() });
    }
    if (url.endsWith("/register")) {
      return jsonResponse({ user_id: crypto.randomUUID(), personal_space_id: crypto.randomUUID() }, 201);
    }
    return jsonResponse({ status: "accepted" }, 202);
  });
  render(
    <I18nProvider>
      <RouterProvider>
        <RegisterPage />
      </RouterProvider>
    </I18nProvider>,
  );

  fireEvent.change(await screen.findByRole("textbox", { name: "邮箱" }), { target: { value: "alice@example.com" } });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));
  await screen.findByText("验证码已发送");
  fireEvent.change(screen.getByLabelText("6 位验证码"), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "验证" }));
  await screen.findByText("身份验证完成");
  fireEvent.change(screen.getByLabelText("设置密码"), { target: { value: "correct horse battery" } });
  fireEvent.change(screen.getByLabelText("确认密码"), { target: { value: "correct horse battery" } });
  fireEvent.click(screen.getByLabelText("我已阅读并同意服务条款和隐私政策"));
  fireEvent.click(screen.getByRole("button", { name: "创建 AgentEra 账户" }));

  await waitFor(() => expect(calls.some((call) => call.url.endsWith("/register"))).toBe(true));
  const registration = calls.find((call) => call.url.endsWith("/register"));
  expect(registration?.body).toMatchObject({
    kind: "email",
    verification_receipt: "verified-receipt",
    terms_version: "2026-07",
    privacy_version: "2026-07",
  });
});

test("supports mainland phone registration as an explicit identity choice", async () => {
  const fetchMock = vi.spyOn(window, "fetch").mockImplementation(async (input, init) => {
    if (String(input) === "/api/v1/legal/current") {
      return jsonResponse({ terms_version: "2026-07", privacy_version: "2026-07" });
    }
    return jsonResponse({ status: "accepted" }, 202);
  });
  render(
    <I18nProvider>
      <RouterProvider>
        <RegisterPage />
      </RouterProvider>
    </I18nProvider>,
  );

  fireEvent.click(await screen.findByRole("radio", { name: "中国大陆手机号" }));
  fireEvent.change(screen.getByRole("textbox", { name: "中国大陆手机号" }), { target: { value: "13800138000" } });
  fireEvent.click(screen.getByRole("button", { name: "发送验证码" }));

  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  const [, init] = fetchMock.mock.calls[1];
  expect(JSON.parse(String(init?.body))).toMatchObject({
    kind: "phone",
    destination: "13800138000",
    purpose: "registration",
  });
});
