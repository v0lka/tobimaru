import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type APInfo, type ClientInfo } from "../api";
import { useSSE } from "../sse";

type SortKey = "channel" | "rssi" | "last_seen";

export default function MapPage() {
  const [aps, setAPs] = useState<APInfo[]>([]);
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [filter, setFilter] = useState("");
  const [sortBy, setSortBy] = useState<SortKey>("last_seen");

  useEffect(() => {
    let mounted = true;
    const tick = async () => {
      try {
        const [a, c] = await Promise.all([api.aps(), api.clients()]);
        if (!mounted) return;
        setAPs(a.items);
        setClients(c.items);
      } catch {}
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  // Live updates via SSE.
  useSSE(
    useCallback((eventName, data) => {
      if (eventName === "ap" && Array.isArray(data)) setAPs(data as APInfo[]);
      if (eventName === "client" && Array.isArray(data)) setClients(data as ClientInfo[]);
    }, []),
  );

  const filteredAPs = useMemo(() => {
    let result = aps;
    if (filter) {
      const f = filter.toLowerCase();
      result = result.filter(
        (a) =>
          a.ssid.toLowerCase().includes(f) ||
          a.bssid.toLowerCase().includes(f),
      );
    }
    return [...result].sort((a, b) => {
      switch (sortBy) {
        case "channel":
          return a.channel - b.channel;
        case "rssi":
          return b.rssi - a.rssi;
        case "last_seen":
        default:
          return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      }
    });
  }, [aps, filter, sortBy]);

  const filteredClients = useMemo(() => {
    let result = clients;
    if (filter) {
      const f = filter.toLowerCase();
      result = result.filter(
        (c) =>
          c.mac.toLowerCase().includes(f) ||
          (c.ssid ?? "").toLowerCase().includes(f) ||
          (c.bssid ?? "").toLowerCase().includes(f),
      );
    }
    return [...result].sort((a, b) => {
      switch (sortBy) {
        case "channel":
          return a.channel - b.channel;
        case "rssi":
          return b.rssi - a.rssi;
        case "last_seen":
        default:
          return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      }
    });
  }, [clients, filter, sortBy]);

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Environment Map</h1>
      <div className="grid gap-4 grid-cols-3">
        <Stat label="Access Points" value={aps.length} />
        <Stat label="Clients" value={clients.length} />
        <Stat label="Associated" value={clients.filter((c) => c.associated).length} />
      </div>

      <div className="card mt-4 flex gap-3 items-center">
        <input
          className="input min-w-[14rem]"
          placeholder="Search SSID, BSSID, or MAC…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <label className="stat-label">Sort:</label>
        <select
          className="input"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as SortKey)}
        >
          <option value="last_seen">Last Seen</option>
          <option value="channel">Channel</option>
          <option value="rssi">RSSI</option>
        </select>
      </div>

      <section className="card mt-4">
        <h2 className="stat-label mb-2">Access Points</h2>
        <Table
          headers={["BSSID", "SSID", "Channel", "RSSI", "Beacons", "Last Seen"]}
          rows={filteredAPs.map((a) => [
            <span className="mono">{a.bssid}</span>,
            a.hidden ? <span className="text-slate-500">&lt;hidden&gt;</span> : a.ssid,
            a.channel,
            `${a.rssi} dBm`,
            a.beacon_count,
            new Date(a.last_seen).toLocaleString(),
          ])}
        />
      </section>

      <section className="card">
        <h2 className="stat-label mb-2">Clients</h2>
        <Table
          headers={["MAC", "Associated", "BSSID", "SSID", "Channel", "RSSI", "Frames", "Last Seen"]}
          rows={filteredClients.map((c) => [
            <span className="mono">{c.mac}</span>,
            c.associated ? <span className="pill-ok">yes</span> : <span className="pill-muted">no</span>,
            <span className="mono">{c.bssid ?? "—"}</span>,
            c.ssid ?? "",
            c.channel,
            `${c.rssi} dBm`,
            c.frame_count,
            new Date(c.last_seen).toLocaleString(),
          ])}
        />
      </section>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

function Table({ headers, rows }: { headers: string[]; rows: React.ReactNode[][] }) {
  if (rows.length === 0) {
    return <div className="text-slate-500 text-center py-6">No data.</div>;
  }
  return (
    <table className="w-full">
      <thead>
        <tr>
          {headers.map((h) => (
            <th key={h} className="text-left py-2 px-3 stat-label border-b border-border">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((cells, i) => (
          <tr key={i} className="hover:bg-sky-500/5">
            {cells.map((c, j) => (
              <td key={j} className="py-2 px-3 border-b border-border">
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
