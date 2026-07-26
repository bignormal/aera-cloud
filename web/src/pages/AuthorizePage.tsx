import { useEffect, useRef, useState } from "react";
import {
  APIError,
  approveAuthorization,
  getProfile,
  type AccountProfile,
} from "../api/client";
import { getCSRFToken } from "../auth/csrf";
import {
  Card,
  PageFrame,
  SpinnerLabel,
  StatusMessage,
} from "../components/Layout";
import { useI18n } from "../i18n";
import { Link, useRouter } from "../router";

const requestIDPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validDesktopRedirect(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return (
      parsed.protocol === "http:" &&
      parsed.hostname === "127.0.0.1" &&
      parsed.port !== "" &&
      parsed.pathname === "/agentera/oauth/callback" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.searchParams.has("code") &&
      parsed.searchParams.has("state")
    );
  } catch {
    return false;
  }
}

function redirectBrowserToDesktop(uri: string): void {
  window.location.assign(uri);
}

export function AuthorizePage({
  redirectToDesktop = redirectBrowserToDesktop,
}: {
  redirectToDesktop?: (uri: string) => void;
}) {
  const { t } = useI18n();
  const { location } = useRouter();
  const requestID =
    new URLSearchParams(location.search).get("request_id") ?? "";
  const [profile, setProfile] = useState<AccountProfile | null>(null);
  const [state, setState] = useState<
    "loading" | "ready" | "unauthenticated" | "working" | "error"
  >("loading");
  const approvalStarted = useRef(false);

  useEffect(() => {
    if (!requestIDPattern.test(requestID)) {
      setState("error");
      return;
    }
    let active = true;
    getProfile()
      .then((result) => {
        if (!active) return;
        setProfile(result);
        setState("ready");
      })
      .catch((error) => {
        if (!active) return;
        setState(
          error instanceof APIError && error.status === 401
            ? "unauthenticated"
            : "error",
        );
      });
    return () => {
      active = false;
    };
  }, [requestID]);

  useEffect(() => {
    if (state !== "ready" || approvalStarted.current) return;
    approvalStarted.current = true;
    if (!getCSRFToken()) {
      setState("unauthenticated");
      return;
    }
    setState("working");
    void approveAuthorization(requestID)
      .then((result) => {
        if (!validDesktopRedirect(result.redirect_uri)) {
          setState("error");
          return;
        }
        redirectToDesktop(result.redirect_uri);
      })
      .catch(() => setState("error"));
  }, [redirectToDesktop, requestID, state]);

  return (
    <PageFrame compact>
      <Card className="auth-card login-return-card">
        {state === "loading" && <SpinnerLabel />}
        {state === "unauthenticated" && (
          <>
            <h1>{t("reauthenticate")}</h1>
            <Link
              className="primary-link"
              href={`/login?next=${encodeURIComponent(`/authorize?request_id=${requestID}`)}`}
            >
              {t("login")}
            </Link>
          </>
        )}
        {state === "error" && (
          <StatusMessage tone="error">
            {t("authorizationExpired")}
          </StatusMessage>
        )}
        {(state === "ready" || state === "working") && (
          <>
            <div className="approval-icon">A</div>
            <h1>{t("loginReturnTitle")}</h1>
            <p className="lede">{t("loginReturnSubtitle")}</p>
            {profile && (
              <div className="account-chip">
                <span>{t("signedInAs")}</span>
                <strong>
                  {profile.nickname || profile.user_id.slice(0, 8)}
                </strong>
              </div>
            )}
            {state === "working" && (
              <StatusMessage>{t("loginReturning")}</StatusMessage>
            )}
          </>
        )}
        {state === "error" && (
          <Link
            className="primary-link"
            href={`/login?next=${encodeURIComponent(`/authorize?request_id=${requestID}`)}`}
          >
            {t("retryLogin")}
          </Link>
        )}
      </Card>
    </PageFrame>
  );
}
