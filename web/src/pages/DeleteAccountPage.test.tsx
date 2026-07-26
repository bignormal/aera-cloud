import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { I18nProvider } from "../i18n";
import { PublicConfigProvider } from "../public-config";
import { RouterProvider } from "../router";
import { DeleteAccountPage } from "./DeleteAccountPage";

const verifiedConfig = {
  environment: "production",
  public_registration_enabled: true,
  registration_mode: "verified",
  registration_identity_kinds: ["email", "phone"],
  identity_verification_available: true,
};

function renderDeletion() {
  window.history.replaceState(null, "", "/delete-account");
  window.localStorage.setItem("agentera.csrf_token", "c".repeat(43));
  return render(
    <I18nProvider>
      <PublicConfigProvider>
        <RouterProvider>
          <DeleteAccountPage />
        </RouterProvider>
      </PublicConfigProvider>
    </I18nProvider>,
  );
}

test("discloses owned workspace deletion without sending the displayed count", async () => {
  const fetchMock = vi
    .spyOn(window, "fetch")
    .mockImplementation(async (input, init) => {
      const path = String(input);
      if (path === "/api/v1/public/config") {
        return new Response(JSON.stringify(verifiedConfig), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path === "/api/v1/accounts/me") {
        return new Response(
          JSON.stringify({
            user_id: "10000000-0000-4000-8000-000000000001",
            personal_space_id: "20000000-0000-4000-8000-000000000002",
            nickname: "Alice",
            status: "active",
            identity_kinds: ["email"],
            owned_workspace_count: 3,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (path === "/api/v1/verification/challenges") {
        return new Response(JSON.stringify({ status: "accepted" }), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (path === "/api/v1/verification/challenges/verify") {
        return new Response(
          JSON.stringify({
            status: "verified",
            receipt: "deletion-receipt",
            expires_at: "2026-07-20T09:10:00Z",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (path === "/api/v1/accounts/deletion") {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected request: ${path} ${init?.method ?? "GET"}`);
    });

  renderDeletion();

  expect(await screen.findByText(/此账户拥有 3 个工作空间/)).toBeVisible();
  expect(
    screen.getByText(/不会删除本机 Hermes 会话、Memory、文件或学习成果/),
  ).toBeVisible();

  fireEvent.change(
    screen.getByLabelText("用于接收验证码的已绑定邮箱或手机号"),
    {
      target: { value: "alice@example.com" },
    },
  );
  fireEvent.click(screen.getByRole("button", { name: "发送注销验证码" }));
  await screen.findByLabelText("6 位验证码");
  fireEvent.change(screen.getByLabelText("6 位验证码"), {
    target: { value: "123456" },
  });
  fireEvent.click(screen.getByRole("button", { name: "验证注销身份" }));
  await screen.findByLabelText("当前密码");
  fireEvent.change(screen.getByLabelText("当前密码"), {
    target: { value: "correct horse battery" },
  });

  const deleteButton = screen.getByRole("button", {
    name: "开始 7 天注销冷静期",
  });
  expect(deleteButton).toBeDisabled();
  fireEvent.click(
    screen.getByLabelText("我理解云端账户注销不会删除本地 Hermes 数据"),
  );
  expect(deleteButton).toBeEnabled();
  fireEvent.click(deleteButton);

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/accounts/deletion",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          current_password: "correct horse battery",
          verification_receipt: "deletion-receipt",
        }),
      }),
    );
  });
});

test("keeps deletion unavailable when the owned workspace count cannot be loaded", async () => {
  vi.spyOn(window, "fetch").mockImplementation(async (input) => {
    if (String(input) === "/api/v1/public/config") {
      return new Response(JSON.stringify(verifiedConfig), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({
        error: { code: "service_unavailable", request_id: "request-1" },
      }),
      { status: 503, headers: { "Content-Type": "application/json" } },
    );
  });

  renderDeletion();

  expect(await screen.findByText("服务暂时不可用，请稍后重试。")).toBeVisible();
  fireEvent.change(
    screen.getByLabelText("用于接收验证码的已绑定邮箱或手机号"),
    {
      target: { value: "alice@example.com" },
    },
  );
  expect(screen.getByRole("button", { name: "发送注销验证码" })).toBeDisabled();
});

test("direct internal beta makes deletion and recovery unavailable without loading account data", async () => {
  window.history.replaceState(null, "", "/delete-account?mode=recover");
  const fetchMock = vi.spyOn(window, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({
        environment: "internal_beta",
        public_registration_enabled: true,
        registration_mode: "direct",
        registration_identity_kinds: ["email"],
        identity_verification_available: false,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  );

  renderDeletion();

  expect(
    await screen.findByRole("heading", { name: "当前内测暂不支持此功能" }),
  ).toBeVisible();
  expect(
    screen.getByText(/暂不支持找回密码、身份绑定或注销恢复/),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "发送恢复验证码" }),
  ).not.toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledOnce();
});
