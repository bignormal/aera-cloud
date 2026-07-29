import { useEffect, useState } from "react";
import {
  APIError,
  bindIdentity,
  getProfile,
  logout,
  removeIdentity,
  sendVerification,
  verifyIdentity,
  type AccountProfile,
  type IdentityKind,
} from "../api/client";
import { clearCSRFToken, getCSRFToken } from "../auth/csrf";
import {
  Card,
  PageFrame,
  SpinnerLabel,
  StatusMessage,
} from "../components/Layout";
import { useI18n } from "../i18n";
import { usePublicConfig } from "../public-config";
import { Link, useRouter } from "../router";

export function AccountPage() {
  const { t } = useI18n();
  const { navigate } = useRouter();
  const { config } = usePublicConfig();
  const [profile, setProfile] = useState<AccountProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [destination, setDestination] = useState("");
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [bindStage, setBindStage] = useState<"" | "sent" | "verified">("");
  const [removeKind, setRemoveKind] = useState<IdentityKind | null>(null);
  const [removePassword, setRemovePassword] = useState("");
  const [busy, setBusy] = useState(false);
  const verificationAvailable =
    config?.identity_verification_available === true;

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      setProfile(await getProfile());
    } catch (caught) {
      if (caught instanceof APIError && caught.status === 401) {
        navigate("/login?next=%2Faccount", { replace: true });
      } else {
        setError(t("serviceError"));
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const unboundKind: IdentityKind | null =
    !verificationAvailable || !profile
      ? null
      : profile.identity_kinds.includes("email")
        ? profile.identity_kinds.includes("phone")
          ? null
          : "phone"
        : "email";
  const missingKind =
    unboundKind && config?.registration_identity_kinds.includes(unboundKind)
      ? unboundKind
      : null;

  const requireFreshLogin = (): boolean => {
    if (getCSRFToken()) return true;
    setError(t("reauthenticate"));
    return false;
  };

  const sendBindCode = async () => {
    if (!missingKind || !requireFreshLogin()) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await sendVerification(missingKind, destination, "bind_identity");
      setBindStage("sent");
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  const verifyBindCode = async () => {
    if (!missingKind) return;
    setBusy(true);
    setError("");
    try {
      const result = await verifyIdentity(
        missingKind,
        destination,
        "bind_identity",
        code,
      );
      setReceipt(result.receipt);
      setBindStage("verified");
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  const bind = async () => {
    if (!requireFreshLogin()) return;
    setBusy(true);
    setError("");
    try {
      await bindIdentity(currentPassword, receipt);
      setMessage(t("identityBound"));
      setDestination("");
      setCode("");
      setReceipt("");
      setCurrentPassword("");
      setBindStage("");
      await load();
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  const confirmRemove = async () => {
    if (!removeKind || !requireFreshLogin()) return;
    setBusy(true);
    setError("");
    try {
      await removeIdentity(removeKind, removePassword);
      setMessage(t("identityRemoved"));
      setRemoveKind(null);
      setRemovePassword("");
      await load();
    } catch (caught) {
      setError(
        caught instanceof APIError && caught.code === "last_identity"
          ? t("lastIdentity")
          : t("serviceError"),
      );
    } finally {
      setBusy(false);
    }
  };

  const signOut = async () => {
    if (!requireFreshLogin()) return;
    setBusy(true);
    setError("");
    try {
      await logout();
      clearCSRFToken();
      navigate("/login", { replace: true });
    } catch {
      setError(t("serviceError"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PageFrame>
      <div className="dashboard-layout">
        <aside className="side-nav">
          <Link className="active" href="/account">
            {t("accountOverview")}
          </Link>
          <Link href="/devices">{t("devices")}</Link>
          {verificationAvailable && (
            <Link className="danger-link" href="/delete-account">
              {t("deleteTitle")}
            </Link>
          )}
        </aside>
        <div className="content-stack">
          {loading && (
            <Card>
              <SpinnerLabel />
            </Card>
          )}
          {error && <StatusMessage tone="error">{error}</StatusMessage>}
          {message && <StatusMessage tone="success">{message}</StatusMessage>}
          {profile && (
            <>
              <Card>
                <div className="section-heading">
                  <div>
                    <div className="eyebrow">AGENTERA ID</div>
                    <h1>{t("accountOverview")}</h1>
                  </div>
                  <button
                    className="text-button"
                    type="button"
                    onClick={signOut}
                    disabled={busy}
                  >
                    {t("logout")}
                  </button>
                </div>
                <div className="profile-grid">
                  <div>
                    <span>{t("signedInAs")}</span>
                    <strong>
                      {profile.nickname || profile.user_id.slice(0, 8)}
                    </strong>
                  </div>
                  <div>
                    <span>{t("personalSpace")}</span>
                    <code>{profile.personal_space_id.slice(0, 8)}…</code>
                  </div>
                </div>
              </Card>
              <Card>
                <h2>{t("boundIdentities")}</h2>
                {!verificationAvailable && (
                  <StatusMessage tone="warning">
                    {t("internalBetaRecoveryUnavailable")}
                  </StatusMessage>
                )}
                <div className="identity-list">
                  {profile.identity_kinds.map((kind) => (
                    <div className="identity-row" key={kind}>
                      <span className="identity-badge">
                        {kind === "email" ? "@" : "+86"}
                      </span>
                      <strong>
                        {kind === "email"
                          ? t("emailIdentity")
                          : t("phoneIdentity")}
                      </strong>
                      <span className="verified-dot">
                        {verificationAvailable ? "✓" : t("identityUnverified")}
                      </span>
                      {verificationAvailable &&
                        profile.identity_kinds.length > 1 && (
                          <button
                            className="text-button danger"
                            type="button"
                            onClick={() => setRemoveKind(kind)}
                          >
                            {t("remove")}
                          </button>
                        )}
                    </div>
                  ))}
                </div>
                {verificationAvailable && removeKind && (
                  <div className="security-panel">
                    <label>
                      <span>{t("currentPassword")}</span>
                      <input
                        type="password"
                        value={removePassword}
                        onChange={(event) =>
                          setRemovePassword(event.target.value)
                        }
                        autoComplete="current-password"
                      />
                    </label>
                    <div className="button-row">
                      <button
                        className="danger-button"
                        type="button"
                        disabled={busy || removePassword.length < 10}
                        onClick={confirmRemove}
                      >
                        {t("remove")}
                      </button>
                      <button
                        className="text-button"
                        type="button"
                        onClick={() => setRemoveKind(null)}
                      >
                        {t("cancel")}
                      </button>
                    </div>
                  </div>
                )}
              </Card>
              {missingKind && (
                <Card>
                  <h2>{t("bindIdentity")}</h2>
                  <div className="form-stack">
                    <label>
                      <span>
                        {missingKind === "email" ? t("email") : t("phone")}
                      </span>
                      <input
                        type={missingKind === "email" ? "email" : "tel"}
                        value={destination}
                        onChange={(event) => {
                          setDestination(event.target.value);
                          setBindStage("");
                          setReceipt("");
                        }}
                        autoComplete={missingKind === "email" ? "email" : "tel"}
                      />
                    </label>
                    <button
                      className="secondary-button"
                      type="button"
                      disabled={busy || !destination}
                      onClick={sendBindCode}
                    >
                      {t("sendCode")}
                    </button>
                    {(bindStage === "sent" || bindStage === "verified") && (
                      <label>
                        <span>{t("code")}</span>
                        <input
                          inputMode="numeric"
                          value={code}
                          onChange={(event) =>
                            setCode(
                              event.target.value.replace(/\D/g, "").slice(0, 6),
                            )
                          }
                          autoComplete="one-time-code"
                        />
                      </label>
                    )}
                    {bindStage === "sent" && (
                      <button
                        className="secondary-button"
                        type="button"
                        disabled={busy || code.length !== 6}
                        onClick={verifyBindCode}
                      >
                        {t("verify")}
                      </button>
                    )}
                    {bindStage === "verified" && (
                      <>
                        <StatusMessage tone="success">
                          {t("identityVerified")}
                        </StatusMessage>
                        <label>
                          <span>{t("currentPassword")}</span>
                          <input
                            type="password"
                            value={currentPassword}
                            onChange={(event) =>
                              setCurrentPassword(event.target.value)
                            }
                            autoComplete="current-password"
                          />
                        </label>
                        <button
                          className="primary-button"
                          type="button"
                          disabled={busy || currentPassword.length < 10}
                          onClick={bind}
                        >
                          {t("bind")}
                        </button>
                      </>
                    )}
                  </div>
                </Card>
              )}
              <Card>
                <h2>{t("passwordSecurity")}</h2>
                <p className="muted">{t("passwordDesktopNote")}</p>
              </Card>
            </>
          )}
        </div>
      </div>
    </PageFrame>
  );
}
