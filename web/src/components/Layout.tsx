import type { ReactNode } from "react";
import { useI18n } from "../i18n";
import { Link } from "../router";

export function Brand() {
  const { t } = useI18n();
  return (
    <Link className="brand" href="/account" aria-label={`${t("brand")} ${t("accountCenter")}`}>
      <img src="/aera-icon.png" alt="" width="40" height="40" />
      <span><strong>{t("brand")}</strong><small>{t("accountCenter")}</small></span>
    </Link>
  );
}

export function LanguageSwitch() {
  const { locale, setLocale, t } = useI18n();
  return (
    <button
      type="button"
      className="language-switch"
      onClick={() => setLocale(locale === "zh-CN" ? "en" : "zh-CN")}
    >
      {locale === "zh-CN" ? t("languageEnglish") : t("languageChinese")}
    </button>
  );
}

export function PageFrame({ children, compact = false }: { children: ReactNode; compact?: boolean }) {
  return (
    <div className="page-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="topbar"><Brand /><LanguageSwitch /></header>
      <main className={compact ? "page-main page-main-compact" : "page-main"}>{children}</main>
      <footer>© 2026 Aera · 独立账户体系</footer>
    </div>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`card ${className}`.trim()}>{children}</section>;
}

export function StatusMessage({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "success" | "error" | "warning" }) {
  return <div className={`status status-${tone}`} role={tone === "error" ? "alert" : "status"}>{children}</div>;
}

export function SpinnerLabel() {
  const { t } = useI18n();
  return <p className="loading" role="status">{t("loading")}</p>;
}
