import { expect, test, type Page, type Route } from "@playwright/test";

const profile = {
  user_id: "10000000-0000-4000-8000-000000000001",
  personal_space_id: "20000000-0000-4000-8000-000000000002",
  nickname: "Alice",
  status: "active",
  identity_kinds: ["email"],
};

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

async function mockAuthenticatedAccount(page: Page) {
  await page.addInitScript(() => sessionStorage.setItem("agentera.csrf_token", "c".repeat(43)));
  await page.route("**/api/v1/accounts/me", (route) => json(route, profile));
  await page.route("**/api/v1/devices", (route) => json(route, {
    devices: [{
      device_id: "30000000-0000-4000-8000-000000000003",
      display_name: "Alice Mac",
      platform: "darwin",
      app_version: "0.1.0",
      status: "active",
      last_seen_at: "2026-07-18T08:00:00Z",
      current: false,
    }],
  }));
}

test("defaults to Chinese, switches to English, and keeps login secrets out of URL and console", async ({ page }) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  await page.route("**/api/v1/browser/login", (route) => json(route, { ...profile, csrf_token: "c".repeat(43) }));
  await page.route("**/api/v1/accounts/me", (route) => json(route, profile));
  await page.goto("/login");

  await expect(page.getByRole("heading", { name: "登录 AgentEra" })).toBeVisible();
  await page.getByLabel("邮箱或手机号").focus();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("密码")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "登录", exact: true })).toBeFocused();
  await page.getByLabel("邮箱或手机号").fill("alice@example.com");
  await page.getByLabel("密码").fill("correct horse battery");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page).toHaveURL(/\/account$/);
  expect(page.url()).not.toContain("alice@example.com");
  expect(page.url()).not.toContain("correct");
  expect(consoleMessages.join("\n")).not.toContain("alice@example.com");
  expect(consoleMessages.join("\n")).not.toContain("correct horse battery");

  await page.getByRole("button", { name: "English" }).click();
  await expect(page.getByRole("heading", { name: "Account overview" })).toBeVisible();
});

test("resets a forgotten password after one-time verification", async ({ page }) => {
  await page.route("**/api/v1/verification/challenges", (route) => json(route, { status: "accepted" }, 202));
  await page.route("**/api/v1/verification/challenges/verify", (route) => json(route, {
    status: "verified", receipt: "reset-receipt", expires_at: "2026-07-18T09:10:00Z",
  }));
  await page.route("**/api/v1/accounts/password/reset", (route) => route.fulfill({ status: 204 }));
  await page.goto("/forgot-password");

  await page.getByLabel("邮箱或手机号").fill("alice@example.com");
  await page.getByRole("button", { name: "发送验证码" }).click();
  await page.getByLabel("6 位验证码").fill("123456");
  await page.getByRole("button", { name: "验证", exact: true }).click();
  await page.getByLabel("设置密码").fill("new correct password");
  await page.getByLabel("确认密码").fill("new correct password");
  await page.getByRole("button", { name: "重置密码" }).click();

  await expect(page.getByText("密码已重置，所有旧设备会话已撤销。")).toBeVisible();
  expect(page.url()).not.toContain("alice@example.com");
  expect(page.url()).not.toContain("123456");
});

test("binds a verified second identity after current-password reauthentication", async ({ page }) => {
  await mockAuthenticatedAccount(page);
  await page.route("**/api/v1/verification/challenges", (route) => json(route, { status: "accepted" }, 202));
  await page.route("**/api/v1/verification/challenges/verify", (route) => json(route, {
    status: "verified", receipt: "bind-receipt", expires_at: "2026-07-18T09:10:00Z",
  }));
  await page.route("**/api/v1/accounts/identities/bind", (route) => route.fulfill({ status: 204 }));
  await page.goto("/account");

  await page.getByLabel("中国大陆手机号").fill("13800138000");
  await page.getByRole("button", { name: "发送验证码" }).click();
  await page.getByLabel("6 位验证码").fill("123456");
  await page.getByRole("button", { name: "验证", exact: true }).click();
  await page.getByLabel("当前密码").fill("correct horse battery");
  await page.getByRole("button", { name: "确认绑定" }).click();

  await expect(page.getByText("新的登录方式已绑定。")).toBeVisible();
});

test("does not pretend sign-out succeeded when the server cannot revoke the session", async ({ page }) => {
  await mockAuthenticatedAccount(page);
  await page.route("**/api/v1/browser/logout", (route) => json(route, {
    error: { code: "service_unavailable", message: "retry later" },
  }, 503));
  await page.goto("/account");

  await page.getByRole("button", { name: "退出网页账户" }).click();

  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByText("服务暂时不可用，请稍后重试。")).toBeVisible();
  await expect(page.evaluate(() => sessionStorage.getItem("agentera.csrf_token"))).resolves.toBe("c".repeat(43));
});

test("shows and explicitly revokes an active device before authorization retry", async ({ page }) => {
  await mockAuthenticatedAccount(page);
  await page.route("**/api/v1/devices/*", (route) => route.fulfill({ status: 204 }));
  await page.goto("/devices?reason=device_limit");

  await expect(page.getByText("已达到 5 台活跃设备上限")).toBeVisible();
  await expect(page.getByText("Alice Mac")).toBeVisible();
  await page.getByRole("button", { name: "撤销这台设备" }).click();
  await page.getByRole("button", { name: "确认撤销" }).click();
  await expect(page.getByText("设备已撤销，可以返回 AgentEra Studio 重试登录")).toBeVisible();
});

test("recovers a pending deletion through a verified identity without URL leakage", async ({ page }) => {
  await page.route("**/api/v1/verification/challenges", (route) => json(route, { status: "accepted" }, 202));
  await page.route("**/api/v1/verification/challenges/verify", (route) => json(route, {
    status: "verified", receipt: "recovery-receipt", expires_at: "2026-07-18T09:10:00Z",
  }));
  await page.route("**/api/v1/accounts/deletion/recover", (route) => route.fulfill({ status: 204 }));
  await page.goto("/delete-account?mode=recover");

  await page.getByLabel("邮箱或手机号").fill("alice@example.com");
  await page.getByRole("button", { name: "发送恢复验证码" }).click();
  await page.getByLabel("6 位验证码").fill("123456");
  await page.getByRole("button", { name: "验证恢复身份" }).click();
  await page.getByLabel("账户密码").fill("correct horse battery");
  await page.getByRole("button", { name: "恢复账户" }).click();

  await expect(page.getByText("账户已恢复，旧设备仍需重新登录")).toBeVisible();
  expect(page.url()).not.toContain("alice@example.com");
  expect(page.url()).not.toContain("123456");
});

test("warns that cloud deletion preserves local Hermes data before entering the cooling-off period", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("agentera.csrf_token", "c".repeat(43)));
  await page.route("**/api/v1/verification/challenges", (route) => json(route, { status: "accepted" }, 202));
  await page.route("**/api/v1/verification/challenges/verify", (route) => json(route, {
    status: "verified", receipt: "deletion-receipt", expires_at: "2026-07-18T09:10:00Z",
  }));
  await page.route("**/api/v1/accounts/deletion", (route) => route.fulfill({ status: 204 }));
  await page.goto("/delete-account");

  await expect(page.getByText(/不会删除本机 Hermes 会话、Memory、文件或学习成果/)).toBeVisible();
  await page.getByLabel("用于接收验证码的已绑定邮箱或手机号").fill("alice@example.com");
  await page.getByRole("button", { name: "发送注销验证码" }).click();
  await page.getByLabel("6 位验证码").fill("123456");
  await page.getByRole("button", { name: "验证注销身份" }).click();
  await page.getByLabel("当前密码").fill("correct horse battery");
  await page.getByLabel("我理解云端账户注销不会删除本地 Hermes 数据").check();
  await page.getByRole("button", { name: "开始 7 天注销冷静期" }).click();

  await expect(page.getByText("账户已进入 7 天注销冷静期，所有云端设备会话已撤销。")).toBeVisible();
});

test("supports OAuth cancel and maps an expired approval without exposing callback values", async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("agentera.csrf_token", "c".repeat(43)));
  await page.route("**/api/v1/accounts/me", (route) => json(route, profile));
  const requestID = "40000000-0000-4000-8000-000000000004";
  await page.goto(`/authorize?request_id=${requestID}`);
  await page.getByRole("button", { name: "取消" }).click();
  await expect(page.getByText("你已取消本次授权，可以关闭此页面。")).toBeVisible();

  await page.route("**/api/v1/oauth/authorize/approve", (route) => json(route, {
    error: { code: "authorization_expired", message: "localized by the client", request_id: requestID },
  }, 400));
  await page.reload();
  await page.getByRole("button", { name: "允许并返回 AgentEra Studio" }).click();
  await expect(page.getByText("授权请求无效或已过期，请返回 AgentEra Studio 重试。")).toBeVisible();
  expect(await page.locator("body").innerText()).not.toContain("callback?code=");
});
