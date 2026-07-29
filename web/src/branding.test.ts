import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { en } from "./i18n/en";
import { zhCN } from "./i18n/zh-CN";

const legacyVisibleBrand =
  /\b(?:AgentEra|WorkBuddy|AionUI)\b|AgentEra Studio|\bHermes\b/iu;

describe("Aera account-center branding", () => {
  it("uses only Aera in customer-facing account copy", () => {
    for (const [locale, messages] of [
      ["en", en],
      ["zh-CN", zhCN],
    ] as const) {
      const copy = JSON.stringify(messages);
      expect(copy, locale).toContain("Aera");
      expect(copy, locale).not.toMatch(legacyVisibleBrand);
    }
  });

  it("uses the Aera title, favicon, footer, and device label", () => {
    const index = readFileSync(resolve("index.html"), "utf8");
    const layout = readFileSync(resolve("src/components/Layout.tsx"), "utf8");
    const pages = [
      "AccountPage.tsx",
      "DevicesPage.tsx",
      "LoginPage.tsx",
      "RegisterPage.tsx",
    ]
      .map((file) => readFileSync(resolve("src/pages", file), "utf8"))
      .join("\n");

    expect(index).toContain("<title>Aera 账户中心</title>");
    expect(index).toContain('href="/aera-icon.png"');
    expect(layout).toContain('src="/aera-icon.png"');
    expect(layout).toContain("© 2026 Aera");
    expect(pages).toContain(" · Aera ");
    expect(pages).toContain("Aera ID");
    expect(pages).toContain("Aera Security");
    expect(`${index}\n${layout}\n${pages}`).not.toMatch(legacyVisibleBrand);
  });

  it("retains the legacy installation header only as a wire contract", () => {
    const client = readFileSync(resolve("src/api/client.ts"), "utf8");
    expect(client).toContain('"X-AgentEra-Installation-ID"');
  });
});
