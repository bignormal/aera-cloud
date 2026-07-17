import { useState, type FormEvent } from "react";
import { resetPassword, sendVerification, verifyIdentity } from "../api/client";
import { Card, PageFrame, StatusMessage } from "../components/Layout";
import { inferIdentityKind, validPassword } from "../components/forms";
import { useI18n } from "../i18n";
import { Link } from "../router";

export function ForgotPasswordPage() {
  const { t } = useI18n();
  const [identity, setIdentity] = useState("");
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [status, setStatus] = useState<"" | "sent" | "verified" | "complete">("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const send = async () => {
    setBusy(true); setError("");
    try {
      await sendVerification(inferIdentityKind(identity), identity, "password_reset");
      setStatus("sent");
    } catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  const verify = async () => {
    setBusy(true); setError("");
    try {
      const result = await verifyIdentity(inferIdentityKind(identity), identity, "password_reset", code);
      setReceipt(result.receipt); setStatus("verified");
    } catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!validPassword(password) || password !== confirmation) { setError(t("passwordMismatch")); return; }
    setBusy(true); setError("");
    try { await resetPassword(receipt, password); setStatus("complete"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };

  return (
    <PageFrame compact>
      <Card className="auth-card">
        <h1>{t("forgotTitle")}</h1>
        {status === "complete" ? (
          <><StatusMessage tone="success">{t("passwordResetComplete")}</StatusMessage><Link className="primary-link" href="/login">{t("backToLogin")}</Link></>
        ) : (
          <>
            {error && <StatusMessage tone="error">{error}</StatusMessage>}
            <div className="form-stack">
              <label><span>{t("identity")}</span><input value={identity} onChange={(event) => { setIdentity(event.target.value); setReceipt(""); setStatus(""); }} autoComplete="username" maxLength={254} /></label>
              <button type="button" className="secondary-button" disabled={busy || !identity} onClick={send}>{t("sendCode")}</button>
              {(status === "sent" || status === "verified") && <StatusMessage tone="success">{t("codeSent")}</StatusMessage>}
              {(status === "sent" || status === "verified") && <label><span>{t("code")}</span><input value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" /></label>}
              {status === "sent" && <button type="button" className="secondary-button" disabled={busy || code.length !== 6} onClick={verify}>{t("verify")}</button>}
            </div>
            {receipt && <form className="form-stack details-form" onSubmit={submit}>
              <StatusMessage tone="success">{t("identityVerified")}</StatusMessage>
              <label><span>{t("setPassword")}</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" minLength={10} maxLength={128} /></label>
              <label><span>{t("confirmPassword")}</span><input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="new-password" minLength={10} maxLength={128} /></label>
              <button type="submit" className="primary-button" disabled={busy}>{t("resetPassword")}</button>
            </form>}
          </>
        )}
        <div className="secondary-link"><Link href="/login">{t("backToLogin")}</Link></div>
      </Card>
    </PageFrame>
  );
}
