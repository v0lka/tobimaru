import { useEffect, useState } from "react";
import { api, type StatusResponse } from "../api";
import { useSSE } from "../sse";
import { useCallback } from "react";

export default function StatusPage() {
  const [status, setStatus] = useState<StatusResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    const tick = () => api.status().then((s) => mounted && setStatus(s)).catch(() => {});
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  useSSE(
    useCallback((eventName, data) => {
      if (eventName === "status") setStatus(data as StatusResponse);
    }, []),
  );

  if (!status) return <div className="text-slate-500 text-center py-6">Loading status…</div>;

  const caps = status.capabilities as Record<string, boolean | number>;

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Agent Status</h1>
      <div className="grid gap-3 grid-cols-3">
        <Stat label="Version" value={status.version || "dev"} />
        <Stat label="Uptime" value={fmtUptime(status.uptime_seconds)} />
        <Stat label="Started" value={new Date(status.started_at).toLocaleString()} />
        <Stat label="Interface" value={status.monitor_interface || "—"} />
        <Stat label="Channel" value={String(status.current_channel || "—")} />
        <Stat label="SSE Subscribers" value={status.subscribers.sse} />
        <Stat label="APs" value={status.stats.aps} />
        <Stat label="Clients" value={status.stats.clients} />
        <Stat label="Events (24h)" value={status.stats.events_24h} />
      </div>

      <section className="card mt-4">
        <h2 className="stat-label mb-2">Capabilities</h2>
        <ul className="space-y-1">
          <CapLine label="Monitor mode" ok={!!caps.monitor_mode} />
          <CapLine label="Frame injection" ok={!!caps.frame_injection} />
          <CapLine label="Channel hopping" ok={!!caps.channel_hopping} />
        </ul>
        {status.platform_limitations.length > 0 && (
          <div className="mt-3 p-3 border border-amber-500 bg-amber-500/10 rounded">
            <strong>Platform limitations:</strong>
            <ul className="mt-1 list-disc pl-5">
              {status.platform_limitations.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section className="card">
        <h2 className="stat-label mb-2">Build</h2>
        <div>
          Version: <span className="mono">{status.version}</span>
        </div>
        <div>
          Commit: <span className="mono">{status.commit}</span>
        </div>
        <div>
          Built: <span className="mono">{status.build_date}</span>
        </div>
      </section>
    </div>
  );
}

function fmtUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${d ? d + "d " : ""}${h}h ${m}m`;
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

function CapLine({ label, ok }: { label: string; ok: boolean }) {
  return (
    <li>
      {label}: {ok ? <span className="pill-ok">yes</span> : <span className="pill-muted">no</span>}
    </li>
  );
}
