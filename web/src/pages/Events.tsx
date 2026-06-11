import { useCallback, useEffect, useState } from "react";
import { api, type SecurityEvent } from "../api";
import { useSSE } from "../sse";

const SEVERITIES = ["", "info", "warning", "critical"] as const;
const PAGE_SIZE = 100;

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState<"" | "info" | "warning" | "critical">("");
  const [eventType, setEventType] = useState("");
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    const params = new URLSearchParams();
    if (severity) params.set("min_severity", severity);
    if (eventType) params.set("event_type", eventType);
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", "0");
    try {
      setLoading(true);
      const r = await api.events(params.toString());
      setEvents(r.items);
      setTotal(r.total);
    } catch {
    } finally {
      setLoading(false);
    }
  }, [severity, eventType]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const hasMore = total > events.length;

  const loadMore = useCallback(async () => {
    const params = new URLSearchParams();
    if (severity) params.set("min_severity", severity);
    if (eventType) params.set("event_type", eventType);
    params.set("limit", String(PAGE_SIZE));
    params.set("offset", String(events.length));
    try {
      setLoading(true);
      const r = await api.events(params.toString());
      setEvents((prev) => [...prev, ...r.items]);
      setTotal(r.total);
    } catch {
    } finally {
      setLoading(false);
    }
  }, [severity, eventType, events.length]);

  const SEV_ORDER: Record<string, number> = { info: 0, warning: 1, critical: 2 };

  useSSE(
    useCallback(
      (eventName, data) => {
        if (eventName !== "event") return;
        const ev = data as SecurityEvent;
        if (severity && (SEV_ORDER[ev.severity] ?? -1) < SEV_ORDER[severity]) return;
        if (eventType && ev.event_type !== eventType) return;
        setEvents((prev) => [ev, ...prev].slice(0, 1000));
        setTotal((t) => t + 1);
      },
      [severity, eventType],
    ),
  );

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Security Events</h1>
      <p className="text-slate-400 mb-4">Total stored events: {total}</p>
      <div className="card flex gap-3 items-center">
        <label className="stat-label">Severity:</label>
        <select
          className="input"
          value={severity}
          onChange={(e) => setSeverity(e.target.value as typeof severity)}
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s || "any"}
            </option>
          ))}
        </select>
        <label className="stat-label">Type:</label>
        <input
          className="input"
          placeholder="e.g. deauth_flood"
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
        />
        <button className="btn" onClick={refresh}>
          Apply
        </button>
      </div>
      <div className="card">
        {events.length === 0 ? (
          <div className="text-slate-500 text-center py-6">No events.</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr>
                {["Time", "Type", "Severity", "Source", "BSSID", "SSID", "Channel", "Description"].map((h) => (
                  <th key={h} className="text-left py-2 px-3 stat-label border-b border-border">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i} className="hover:bg-sky-500/5">
                  <td className="py-2 px-3 border-b border-border">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="py-2 px-3 border-b border-border">{e.event_type}</td>
                  <td className="py-2 px-3 border-b border-border">
                    <span className={`pill-${e.severity}`}>{e.severity}</span>
                  </td>
                  <td className="py-2 px-3 border-b border-border mono">{e.src_mac ?? "—"}</td>
                  <td className="py-2 px-3 border-b border-border mono">{e.bssid ?? "—"}</td>
                  <td className="py-2 px-3 border-b border-border">{e.ssid ?? ""}</td>
                  <td className="py-2 px-3 border-b border-border">{e.channel}</td>
                  <td className="py-2 px-3 border-b border-border">{e.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {hasMore && (
          <div className="text-center py-4">
            <button className="btn" onClick={loadMore} disabled={loading}>
              {loading ? "Loading…" : "Load more"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
