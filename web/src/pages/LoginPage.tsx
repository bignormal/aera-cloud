import { useState, type FormEvent } from "react";
import { APIError, login } from "../api/client";
import { setCSRFToken } from "../auth/csrf";
import { Card, PageFrame, StatusMessage } from "../components/Layout";
import { errorKey } from "../components/forms";
import { useI18n } from "../i18n";
import { isSafeInternalTarget, Link, useRouter } from "../router";

export function LoginPage() {
  const { t } = useI18n();
  const { location, navigate } = useRouter();
  const [identity, setIdentity] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const params = new URLSearchParams(location.search);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await login(identity, password);
      setCSRFToken(result.csrf_token);
      const requested = params.get("next") ?? "";
      navigate(isSafeInternalTarget(requested) ? requested : "/account", { replace: true });
    } catch (caught) {
      if (caught instanceof APIError && caught.code === "account_pending_deletion") {
        setError("account_pending_deletion");
      } else {
        setError(t(errorKey(caught)));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <PageFrame compact>
      <Card className="auth-card">
        <div className="eyebrow">AGENTERA ID</div>
        <h1>{t("loginTitle")}</h1>
        <p className="lede">{t("loginSubtitle")}</p>
        {params.get("registered") === "1" && <StatusMessage tone="success">{t("registered")}</StatusMessage>}
        {error === "account_pending_deletion" ? (
          <StatusMessage tone="warning"><Link href="/delete-account?mode=recover">{t("recoverDeletion")}</Link></StatusMessage>
        ) : error ? <StatusMessage tone="error">{error}</StatusMessage> : null}
        <form onSubmit={submit} className="form-stack">
          <label>
            <span>{t("identity")}</span>
            <input
              value={identity}
              onChange={(event) => setIdentity(event.target.value)}
              autoComplete="username"
              inputMode="email"
              maxLength={254}
              required
            />
          </label>
          <label>
            <span>{t("password")}</span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              minLength={10}
              maxLength={128}
              required
            />
          </label>
          <button className="primary-button" type="submit" disabled={busy}>{t("login")}</button>
        </form>
        <div className="link-row">
          <Link href="/register">{t("createAccount")}</Link>
          <Link href="/forgot-password">{t("forgotPassword")}</Link>
        </div>
        <div className="secondary-link"><Link href="/delete-account?mode=recover">{t("recoverDeletion")}</Link></div>
      </Card>
    </PageFrame>
  );
}
