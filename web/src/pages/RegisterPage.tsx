import { useEffect, useState, type FormEvent } from "react";
import {
  getLegalDocuments,
  registerAccount,
  sendVerification,
  verifyIdentity,
  type IdentityKind,
  type LegalDocuments,
} from "../api/client";
import { Card, PageFrame, SpinnerLabel, StatusMessage } from "../components/Layout";
import { validPassword } from "../components/forms";
import { useI18n } from "../i18n";
import { Link, useRouter } from "../router";

export function RegisterPage() {
  const { t } = useI18n();
  const { navigate } = useRouter();
  const [legal, setLegal] = useState<LegalDocuments | null>(null);
  const [kind, setKind] = useState<IdentityKind>("email");
  const [destination, setDestination] = useState("");
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [nickname, setNickname] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [status, setStatus] = useState<"" | "sent" | "verified" | "complete">("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    getLegalDocuments().then((documents) => {
      if (active) setLegal(documents);
    }).catch(() => {
      if (active) setError(t("serviceError"));
    });
    return () => { active = false; };
  }, [t]);

  const changeKind = (next: IdentityKind) => {
    setKind(next);
    setDestination("");
    setCode("");
    setReceipt("");
    setStatus("");
    setError("");
  };

  const sendCode = async () => {
    setBusy(true);
    setError("");
    try {
      await sendVerification(kind, destination, "registration");
      setStatus("sent");
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  const verifyCode = async () => {
    setBusy(true);
    setError("");
    try {
      const result = await verifyIdentity(kind, destination, "registration", code);
      setReceipt(result.receipt);
      setStatus("verified");
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!validPassword(password) || password !== confirmation) {
      setError(t("passwordMismatch"));
      return;
    }
    if (!accepted || !legal) {
      setError(t("legalRequired"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      await registerAccount({
        kind,
        verification_receipt: receipt,
        password,
        nickname: nickname.trim(),
        terms_version: legal.terms_version,
        privacy_version: legal.privacy_version,
      });
      setStatus("complete");
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  if (!legal && !error) {
    return <PageFrame compact><Card className="auth-card"><SpinnerLabel /></Card></PageFrame>;
  }
  if (status === "complete") {
    return (
      <PageFrame compact>
        <Card className="auth-card completion-card">
          <div className="success-mark">✓</div>
          <h1>{t("registrationComplete")}</h1>
          <button className="primary-button" onClick={() => navigate("/login?registered=1", { replace: true })}>{t("backToLogin")}</button>
        </Card>
      </PageFrame>
    );
  }

  return (
    <PageFrame compact>
      <Card className="auth-card wide-card">
        <div className="eyebrow">AGENTERA ID</div>
        <h1>{t("registerTitle")}</h1>
        {error && <StatusMessage tone="error">{error}</StatusMessage>}
        <fieldset className="identity-choice">
          <legend className="sr-only">Identity type</legend>
          <label><input type="radio" name="kind" checked={kind === "email"} onChange={() => changeKind("email")} />{t("useEmail")}</label>
          <label><input type="radio" name="kind" checked={kind === "phone"} onChange={() => changeKind("phone")} />{t("usePhone")}</label>
        </fieldset>
        <div className="form-stack">
          <label>
            <span>{kind === "email" ? t("email") : t("phone")}</span>
            <input
              value={destination}
              onChange={(event) => { setDestination(event.target.value); setReceipt(""); setStatus(""); }}
              type={kind === "email" ? "email" : "tel"}
              inputMode={kind === "email" ? "email" : "tel"}
              autoComplete={kind === "email" ? "email" : "tel"}
              maxLength={254}
              required
            />
          </label>
          <button className="secondary-button" type="button" disabled={busy || !destination} onClick={sendCode}>{t("sendCode")}</button>
          {(status === "sent" || status === "verified") && <StatusMessage tone="success">{t("codeSent")}</StatusMessage>}
          {(status === "sent" || status === "verified") && (
            <div className="inline-form">
              <label><span>{t("code")}</span><input value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" /></label>
              <button className="secondary-button" type="button" disabled={busy || code.length !== 6} onClick={verifyCode}>{t("verify")}</button>
            </div>
          )}
          {status === "verified" && <StatusMessage tone="success">{t("identityVerified")}</StatusMessage>}
        </div>
        {receipt && (
          <form className="form-stack details-form" onSubmit={submit}>
            <label><span>{t("nickname")}</span><input value={nickname} onChange={(event) => setNickname(event.target.value)} maxLength={80} autoComplete="nickname" /></label>
            <label><span>{t("setPassword")}</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={10} maxLength={128} autoComplete="new-password" required /></label>
            <label><span>{t("confirmPassword")}</span><input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} minLength={10} maxLength={128} autoComplete="new-password" required /></label>
            <label className="checkbox-row"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} />{t("acceptLegal")}</label>
            <button className="primary-button" type="submit" disabled={busy}>{t("createAgentEraAccount")}</button>
          </form>
        )}
        <div className="secondary-link"><Link href="/login">{t("backToLogin")}</Link></div>
      </Card>
    </PageFrame>
  );
}
