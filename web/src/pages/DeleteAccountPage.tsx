import { useEffect, useState, type FormEvent } from "react";
import { getProfile, recoverDeletion, requestDeletion, sendVerification, verifyIdentity } from "../api/client";
import { clearCSRFToken, getCSRFToken } from "../auth/csrf";
import { Card, PageFrame, StatusMessage } from "../components/Layout";
import { inferIdentityKind } from "../components/forms";
import { useI18n } from "../i18n";
import { Link, useRouter } from "../router";

export function DeleteAccountPage() {
  const { t } = useI18n();
  const { location } = useRouter();
  const recoveryMode = new URLSearchParams(location.search).get("mode") === "recover";
  return recoveryMode ? <RecoveryForm /> : <DeletionForm />;
}

function RecoveryForm() {
  const { t } = useI18n();
  const [identity, setIdentity] = useState("");
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState<"" | "sent" | "verified" | "complete">("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const send = async () => {
    setBusy(true); setError("");
    try { await sendVerification(inferIdentityKind(identity), identity, "deletion_recovery"); setStatus("sent"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  const verify = async () => {
    setBusy(true); setError("");
    try { const result = await verifyIdentity(inferIdentityKind(identity), identity, "deletion_recovery", code); setReceipt(result.receipt); setStatus("verified"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  const recover = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    try { await recoverDeletion(identity, password, receipt); setStatus("complete"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  return (
    <PageFrame compact><Card className="auth-card wide-card">
      <h1>{t("recoverTitle")}</h1>
      {error && <StatusMessage tone="error">{error}</StatusMessage>}
      {status === "complete" ? <><StatusMessage tone="success">{t("recoveryComplete")}</StatusMessage><Link className="primary-link" href="/login">{t("backToLogin")}</Link></> : <form className="form-stack" onSubmit={recover}>
        <label><span>{t("identity")}</span><input value={identity} onChange={(event) => { setIdentity(event.target.value); setReceipt(""); setStatus(""); }} autoComplete="username" maxLength={254} /></label>
        <button className="secondary-button" type="button" disabled={busy || !identity} onClick={send}>{t("sendRecoveryCode")}</button>
        {(status === "sent" || status === "verified") && <label><span>{t("code")}</span><input value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" /></label>}
        {status === "sent" && <button className="secondary-button" type="button" disabled={busy || code.length !== 6} onClick={verify}>{t("verifyRecoveryIdentity")}</button>}
        {status === "verified" && <><StatusMessage tone="success">{t("identityVerified")}</StatusMessage><label><span>{t("accountPassword")}</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" minLength={10} maxLength={128} /></label><button className="primary-button" type="submit" disabled={busy || password.length < 10}>{t("recoverAccount")}</button></>}
      </form>}
      <div className="secondary-link"><Link href="/login">{t("backToLogin")}</Link></div>
    </Card></PageFrame>
  );
}

function DeletionForm() {
  const { t } = useI18n();
  const [ownedWorkspaceCount, setOwnedWorkspaceCount] = useState<number | null>(null);
  const [profileLoadFailed, setProfileLoadFailed] = useState(false);
  const [identity, setIdentity] = useState("");
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState("");
  const [password, setPassword] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [status, setStatus] = useState<"" | "sent" | "verified" | "complete">("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    getProfile()
      .then((profile) => {
        if (active) {
          setOwnedWorkspaceCount(profile.owned_workspace_count);
        }
      })
      .catch(() => {
        if (active) {
          setProfileLoadFailed(true);
        }
      });
    return () => { active = false; };
  }, []);
  const send = async () => {
    if (ownedWorkspaceCount === null) { setError(t("serviceError")); return; }
    if (!getCSRFToken()) { setError(t("reauthenticate")); return; }
    setBusy(true); setError("");
    try { await sendVerification(inferIdentityKind(identity), identity, "account_deletion"); setStatus("sent"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  const verify = async () => {
    setBusy(true); setError("");
    try { const result = await verifyIdentity(inferIdentityKind(identity), identity, "account_deletion", code); setReceipt(result.receipt); setStatus("verified"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  const remove = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    try { await requestDeletion(password, receipt); clearCSRFToken(); setStatus("complete"); }
    catch { setError(t("serviceError")); } finally { setBusy(false); }
  };
  return (
    <PageFrame compact><Card className="auth-card wide-card danger-card">
      <div className="danger-symbol">!</div><h1>{t("deleteTitle")}</h1>
      <StatusMessage tone="warning">{t("deleteWarning")}</StatusMessage>
      {ownedWorkspaceCount !== null && <StatusMessage tone="warning">{`${t("ownedWorkspaceDeletionPrefix")}${ownedWorkspaceCount}${t("ownedWorkspaceDeletionSuffix")}`}</StatusMessage>}
      {(profileLoadFailed || error) && <StatusMessage tone="error">{profileLoadFailed ? t("serviceError") : error}</StatusMessage>}
      {status === "complete" ? <><StatusMessage tone="success">{t("deletionRequested")}</StatusMessage><Link className="primary-link" href="/delete-account?mode=recover">{t("recoverDeletion")}</Link></> : <form className="form-stack" onSubmit={remove}>
        <label><span>{t("deletionIdentity")}</span><input value={identity} onChange={(event) => { setIdentity(event.target.value); setReceipt(""); setStatus(""); }} autoComplete="username" /></label>
        <button className="secondary-button" type="button" disabled={busy || !identity || ownedWorkspaceCount === null || profileLoadFailed} onClick={send}>{t("sendDeletionCode")}</button>
        {(status === "sent" || status === "verified") && <label><span>{t("code")}</span><input value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" /></label>}
        {status === "sent" && <button className="secondary-button" type="button" disabled={busy || code.length !== 6} onClick={verify}>{t("verifyDeletionIdentity")}</button>}
        {status === "verified" && <><label><span>{t("currentPassword")}</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" minLength={10} maxLength={128} /></label><label className="checkbox-row"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />{t("confirmDeletion")}</label><button className="danger-button" type="submit" disabled={busy || !confirmed || password.length < 10 || ownedWorkspaceCount === null}>{t("deleteAccount")}</button></>}
      </form>}
      <div className="secondary-link"><Link href="/account">{t("accountOverview")}</Link></div>
    </Card></PageFrame>
  );
}
