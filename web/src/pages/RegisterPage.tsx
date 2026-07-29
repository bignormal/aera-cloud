import { useEffect, useState, type FormEvent } from "react";
import {
  APIError,
  getLegalDocuments,
  login,
  registerAccount,
  sendVerification,
  verifyIdentity,
  type IdentityKind,
  type LegalDocuments,
} from "../api/client";
import { setCSRFToken } from "../auth/csrf";
import {
  Card,
  PageFrame,
  SpinnerLabel,
  StatusMessage,
} from "../components/Layout";
import { validPassword } from "../components/forms";
import { useI18n } from "../i18n";
import { usePublicConfig } from "../public-config";
import {
  isSafeInternalTarget,
  Link,
  useRouter,
  withSafeNextTarget,
} from "../router";

function validDirectEmail(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (
    normalized.length === 0 ||
    normalized.length > 254 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    return false;
  }
  const parts = normalized.split("@");
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  return (
    local.length > 0 &&
    local.length <= 64 &&
    domain.length > 0 &&
    domain.includes(".") &&
    !domain.startsWith(".") &&
    !domain.endsWith(".") &&
    !domain.includes("..")
  );
}

export function RegisterPage() {
  const { t } = useI18n();
  const { location, navigate } = useRouter();
  const {
    config,
    error: configError,
    loading: configLoading,
  } = usePublicConfig();
  const [legal, setLegal] = useState<LegalDocuments | null>(null);
  const [kind, setKind] = useState<IdentityKind>("email");
  const [destination, setDestination] = useState("");
  const [code, setCode] = useState("");
  const [receipt, setReceipt] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [nickname, setNickname] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [status, setStatus] = useState<
    "" | "sent" | "verified" | "returning" | "complete"
  >("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const directRegistration = config?.registration_mode === "direct";

  useEffect(() => {
    if (!config || config.registration_identity_kinds.includes(kind)) return;
    const next = config.registration_identity_kinds[0];
    setKind(next);
    setDestination("");
    setCode("");
    setReceipt("");
    setStatus("");
    setError("");
  }, [config, kind]);

  useEffect(() => {
    let active = true;
    getLegalDocuments()
      .then((documents) => {
        if (active) setLegal(documents);
      })
      .catch(() => {
        if (active) setError(t("serviceError"));
      });
    return () => {
      active = false;
    };
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
      const result = await verifyIdentity(
        kind,
        destination,
        "registration",
        code,
      );
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
    const normalizedEmail = destination.trim().toLowerCase();
    if (directRegistration && !validDirectEmail(normalizedEmail)) {
      setError(t("invalidInternalBetaEmail"));
      return;
    }
    setBusy(true);
    setError("");
    const shared = {
      password,
      nickname: nickname.trim(),
      terms_version: legal.terms_version,
      privacy_version: legal.privacy_version,
    };
    const loginIdentity =
      kind === "email" ? destination.trim().toLowerCase() : destination.trim();
    try {
      if (directRegistration) {
        await registerAccount({
          ...shared,
          kind: "email",
          identity: normalizedEmail,
        });
      } else {
        await registerAccount({
          ...shared,
          kind,
          verification_receipt: receipt,
        });
      }
    } catch (caught) {
      setError(
        caught instanceof APIError && caught.code === "identity_conflict"
          ? t("identityConflict")
          : t("serviceError"),
      );
      setBusy(false);
      return;
    }

    setStatus("returning");
    try {
      const signedIn = await login(loginIdentity, password);
      setCSRFToken(signedIn.csrf_token);
      const requested = new URLSearchParams(location.search).get("next") ?? "";
      navigate(isSafeInternalTarget(requested) ? requested : "/account", {
        replace: true,
      });
    } catch {
      setStatus("complete");
      setError(t("registrationLoginFailed"));
    } finally {
      setBusy(false);
    }
  };

  if ((!legal || configLoading) && !error && !configError) {
    return (
      <PageFrame compact>
        <Card className="auth-card">
          <SpinnerLabel />
        </Card>
      </PageFrame>
    );
  }
  if (configError || !config) {
    return (
      <PageFrame compact>
        <Card className="auth-card">
          <StatusMessage tone="error">{t("serviceError")}</StatusMessage>
        </Card>
      </PageFrame>
    );
  }
  if (!config.public_registration_enabled) {
    return (
      <PageFrame compact>
        <Card className="auth-card">
          <StatusMessage tone="warning">
            {t("registrationUnavailable")}
          </StatusMessage>
          <div className="secondary-link">
            <Link href="/login">{t("backToLogin")}</Link>
          </div>
        </Card>
      </PageFrame>
    );
  }
  if (status === "returning") {
    return (
      <PageFrame compact>
        <Card className="auth-card completion-card">
          <SpinnerLabel />
          <h1>{t("registrationReturning")}</h1>
          <p className="lede">{t("registrationReturningSubtitle")}</p>
        </Card>
      </PageFrame>
    );
  }
  if (status === "complete") {
    return (
      <PageFrame compact>
        <Card className="auth-card completion-card">
          <div className="success-mark">✓</div>
          <h1>{t("registrationComplete")}</h1>
          {error && <StatusMessage tone="warning">{error}</StatusMessage>}
          <button
            className="primary-button"
            onClick={() =>
              navigate(
                withSafeNextTarget("/login?registered=1", location.search),
                { replace: true },
              )
            }
          >
            {t("backToLogin")}
          </button>
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
        {!directRegistration && (
          <fieldset className="identity-choice">
            <legend className="sr-only">Identity type</legend>
            {config.registration_identity_kinds.includes("email") && (
              <label>
                <input
                  type="radio"
                  name="kind"
                  checked={kind === "email"}
                  onChange={() => changeKind("email")}
                />
                {t("useEmail")}
              </label>
            )}
            {config.registration_identity_kinds.includes("phone") && (
              <label>
                <input
                  type="radio"
                  name="kind"
                  checked={kind === "phone"}
                  onChange={() => changeKind("phone")}
                />
                {t("usePhone")}
              </label>
            )}
          </fieldset>
        )}
        {directRegistration && (
          <StatusMessage tone="warning">
            {t("internalBetaRecoveryUnavailable")}
          </StatusMessage>
        )}
        <div className="form-stack">
          <label>
            <span>
              {directRegistration
                ? t("internalBetaLoginEmail")
                : kind === "email"
                  ? t("email")
                  : t("phone")}
            </span>
            <input
              value={destination}
              onChange={(event) => {
                setDestination(event.target.value);
                setReceipt("");
                setStatus("");
              }}
              type={kind === "email" ? "email" : "tel"}
              inputMode={kind === "email" ? "email" : "tel"}
              autoComplete={kind === "email" ? "email" : "tel"}
              maxLength={254}
              required
            />
          </label>
          {!directRegistration && (
            <button
              className="secondary-button"
              type="button"
              disabled={busy || !destination}
              onClick={sendCode}
            >
              {t("sendCode")}
            </button>
          )}
          {!directRegistration &&
            (status === "sent" || status === "verified") && (
              <StatusMessage tone="success">{t("codeSent")}</StatusMessage>
            )}
          {!directRegistration &&
            (status === "sent" || status === "verified") && (
              <div className="inline-form">
                <label>
                  <span>{t("code")}</span>
                  <input
                    value={code}
                    onChange={(event) =>
                      setCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    inputMode="numeric"
                    autoComplete="one-time-code"
                  />
                </label>
                <button
                  className="secondary-button"
                  type="button"
                  disabled={busy || code.length !== 6}
                  onClick={verifyCode}
                >
                  {t("verify")}
                </button>
              </div>
            )}
          {!directRegistration && status === "verified" && (
            <StatusMessage tone="success">
              {t("identityVerified")}
            </StatusMessage>
          )}
        </div>
        {(directRegistration || receipt) && (
          <form className="form-stack details-form" onSubmit={submit}>
            <label>
              <span>{t("nickname")}</span>
              <input
                value={nickname}
                onChange={(event) => setNickname(event.target.value)}
                maxLength={80}
                autoComplete="nickname"
              />
            </label>
            <label>
              <span>{t("setPassword")}</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                minLength={10}
                maxLength={128}
                autoComplete="new-password"
                required
              />
            </label>
            <label>
              <span>{t("confirmPassword")}</span>
              <input
                type="password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                minLength={10}
                maxLength={128}
                autoComplete="new-password"
                required
              />
            </label>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={accepted}
                onChange={(event) => setAccepted(event.target.checked)}
              />
              {t("acceptLegal")}
            </label>
            <button className="primary-button" type="submit" disabled={busy}>
              {t("createAgentEraAccount")}
            </button>
          </form>
        )}
        <div className="secondary-link">
          <Link href={withSafeNextTarget("/login", location.search)}>
            {t("backToLogin")}
          </Link>
        </div>
      </Card>
    </PageFrame>
  );
}
