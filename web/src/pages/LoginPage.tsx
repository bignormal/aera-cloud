import { useState, type FormEvent } from "react";
import {
  APIError,
  login,
  loginWithCode,
  sendVerification,
  verifyIdentity,
} from "../api/client";
import { setCSRFToken } from "../auth/csrf";
import { Card, PageFrame, StatusMessage } from "../components/Layout";
import { errorKey, verificationSendErrorKey } from "../components/forms";
import { useI18n } from "../i18n";
import { usePublicConfig } from "../public-config";
import {
  isSafeInternalTarget,
  Link,
  useRouter,
  withSafeNextTarget,
} from "../router";

type LoginMode = "password" | "code";

export function LoginPage() {
  const { t } = useI18n();
  const { location, navigate } = useRouter();
  const { config } = usePublicConfig();
  const [mode, setMode] = useState<LoginMode>("password");
  const [identity, setIdentity] = useState("");
  const [password, setPassword] = useState("");
  const [phone, setPhone] = useState("");
  const [code, setCode] = useState("");
  const [codeStatus, setCodeStatus] = useState<"" | "sent">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const params = new URLSearchParams(location.search);
  const verificationAvailable =
    config?.identity_verification_available === true;
  const directRegistration = config?.registration_mode === "direct";

  const finishLogin = (csrfToken: string) => {
    setCSRFToken(csrfToken);
    const requested = params.get("next") ?? "";
    navigate(isSafeInternalTarget(requested) ? requested : "/account", {
      replace: true,
    });
  };

  const changeMode = (next: LoginMode) => {
    setMode(next);
    setError("");
    setCode("");
    setCodeStatus("");
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await login(identity, password);
      finishLogin(result.csrf_token);
    } catch (caught) {
      if (
        caught instanceof APIError &&
        caught.code === "account_pending_deletion"
      ) {
        setError("account_pending_deletion");
      } else {
        setError(t(errorKey(caught)));
      }
    } finally {
      setBusy(false);
    }
  };

  const sendLoginCode = async () => {
    setBusy(true);
    setError("");
    try {
      await sendVerification("phone", phone, "login");
      setCodeStatus("sent");
    } catch (caught) {
      setError(t(verificationSendErrorKey(caught)));
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const verified = await verifyIdentity("phone", phone, "login", code);
      const result = await loginWithCode(verified.receipt);
      finishLogin(result.csrf_token);
    } catch (caught) {
      if (
        caught instanceof APIError &&
        caught.code === "account_pending_deletion"
      ) {
        setError("account_pending_deletion");
      } else if (
        caught instanceof APIError &&
        (caught.code === "invalid_or_expired_code" ||
          caught.code === "verification_required" ||
          caught.code === "invalid_credentials")
      ) {
        setError(t("codeLoginError"));
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
        <div className="eyebrow">Aera ID</div>
        <h1>{t("loginTitle")}</h1>
        <p className="lede">{t("loginSubtitle")}</p>
        {params.get("registered") === "1" && (
          <StatusMessage tone="success">{t("registered")}</StatusMessage>
        )}
        {error === "account_pending_deletion" ? (
          <StatusMessage tone="warning">
            {verificationAvailable ? (
              <Link href="/delete-account?mode=recover">
                {t("recoverDeletion")}
              </Link>
            ) : (
              t("internalBetaRecoveryUnavailable")
            )}
          </StatusMessage>
        ) : error ? (
          <StatusMessage tone="error">{error}</StatusMessage>
        ) : null}
        {directRegistration && (
          <StatusMessage tone="warning">
            {t("internalBetaRecoveryUnavailable")}
          </StatusMessage>
        )}
        {verificationAvailable && (
          <fieldset className="identity-choice">
            <legend className="sr-only">Sign-in method</legend>
            <label>
              <input
                type="radio"
                name="login-mode"
                checked={mode === "password"}
                onChange={() => changeMode("password")}
              />
              {t("passwordLoginTab")}
            </label>
            <label>
              <input
                type="radio"
                name="login-mode"
                checked={mode === "code"}
                onChange={() => changeMode("code")}
              />
              {t("codeLoginTab")}
            </label>
          </fieldset>
        )}
        {mode === "password" || !verificationAvailable ? (
          <form onSubmit={submit} className="form-stack">
            <label>
              <span>
                {directRegistration
                  ? t("internalBetaLoginEmail")
                  : t("identity")}
              </span>
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
            <button className="primary-button" type="submit" disabled={busy}>
              {t("login")}
            </button>
          </form>
        ) : (
          <form onSubmit={submitCode} className="form-stack">
            <label>
              <span>{t("phone")}</span>
              <input
                value={phone}
                onChange={(event) => {
                  setPhone(event.target.value);
                  setCodeStatus("");
                }}
                type="tel"
                inputMode="tel"
                autoComplete="tel"
                maxLength={20}
                required
              />
            </label>
            <button
              className="secondary-button"
              type="button"
              disabled={busy || !phone}
              onClick={sendLoginCode}
            >
              {t("sendCode")}
            </button>
            {codeStatus === "sent" && (
              <StatusMessage tone="success">{t("codeSent")}</StatusMessage>
            )}
            {codeStatus === "sent" && (
              <label>
                <span>{t("code")}</span>
                <input
                  value={code}
                  onChange={(event) =>
                    setCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                  }
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                />
              </label>
            )}
            <button
              className="primary-button"
              type="submit"
              disabled={busy || code.length !== 6}
            >
              {t("codeLogin")}
            </button>
          </form>
        )}
        <div className="link-row">
          {config?.public_registration_enabled === true && (
            <Link href={withSafeNextTarget("/register", location.search)}>
              {t("createAccount")}
            </Link>
          )}
          {verificationAvailable && (
            <Link href="/forgot-password">{t("forgotPassword")}</Link>
          )}
        </div>
        {verificationAvailable && (
          <div className="secondary-link">
            <Link href="/delete-account?mode=recover">
              {t("recoverDeletion")}
            </Link>
          </div>
        )}
      </Card>
    </PageFrame>
  );
}
