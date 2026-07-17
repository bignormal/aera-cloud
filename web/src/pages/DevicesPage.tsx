import { useEffect, useState } from "react";
import { APIError, listDevices, revokeDevice, type Device } from "../api/client";
import { Card, PageFrame, SpinnerLabel, StatusMessage } from "../components/Layout";
import { useI18n } from "../i18n";
import { Link, useRouter } from "../router";

function platformLabel(platform: Device["platform"]): string {
  if (platform === "darwin") return "macOS";
  if (platform === "windows") return "Windows";
  return "Linux";
}

export function DevicesPage() {
  const { locale, t } = useI18n();
  const { location, navigate } = useRouter();
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [pending, setPending] = useState<Device | null>(null);
  const [busy, setBusy] = useState(false);
  const limitReached = new URLSearchParams(location.search).get("reason") === "device_limit";

  useEffect(() => {
    let active = true;
    listDevices().then((result) => { if (active) setDevices(result); }).catch((caught) => {
      if (!active) return;
      if (caught instanceof APIError && caught.status === 401) navigate("/login?next=%2Fdevices", { replace: true });
      else setError(t("serviceError"));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const confirm = async () => {
    if (!pending) return;
    setBusy(true); setError("");
    try {
      await revokeDevice(pending.device_id);
      setDevices((current) => current.filter((item) => item.device_id !== pending.device_id));
      setPending(null);
      setMessage(t("deviceRevoked"));
    } catch { setError(t("serviceError")); } finally { setBusy(false); }
  };

  return (
    <PageFrame>
      <div className="dashboard-layout">
        <aside className="side-nav"><Link href="/account">{t("accountOverview")}</Link><Link className="active" href="/devices">{t("devices")}</Link><Link className="danger-link" href="/delete-account">{t("deleteTitle")}</Link></aside>
        <div className="content-stack">
          <Card>
            <div className="eyebrow">AGENTERA SECURITY</div>
            <h1>{t("devices")}</h1>
            {limitReached && <StatusMessage tone="warning"><strong>{t("deviceLimit")}</strong><br />{t("deviceLimitHelp")}</StatusMessage>}
            {error && <StatusMessage tone="error">{error}</StatusMessage>}
            {message && <StatusMessage tone="success">{message}</StatusMessage>}
            {loading ? <SpinnerLabel /> : devices.length === 0 ? <p className="muted">{t("noDevices")}</p> : <div className="device-list">
              {devices.map((device) => <article className="device-row" key={device.device_id}>
                <div className="device-icon">{device.platform === "darwin" ? "⌘" : device.platform === "windows" ? "⊞" : "◇"}</div>
                <div className="device-copy"><strong>{device.display_name}</strong><span>{platformLabel(device.platform)} · AgentEra {device.app_version}</span><small>{t("lastSeen")}: {new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(new Date(device.last_seen_at))}</small></div>
                <button className="secondary-button danger-outline" type="button" onClick={() => setPending(device)}>{t("revokeDevice")}</button>
              </article>)}
            </div>}
          </Card>
          {pending && <Card className="confirmation-card"><h2>{pending.display_name}</h2><p>{t("deviceLimitHelp")}</p><div className="button-row"><button className="danger-button" type="button" disabled={busy} onClick={confirm}>{t("confirmRevoke")}</button><button className="text-button" type="button" disabled={busy} onClick={() => setPending(null)}>{t("cancel")}</button></div></Card>}
        </div>
      </div>
    </PageFrame>
  );
}
