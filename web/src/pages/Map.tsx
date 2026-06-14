import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type APInfo, type ClientInfo } from "../api";
import { useSSE } from "../sse";
import EnvironmentGraph from "./EnvironmentGraph";

type SortKey = "channel" | "rssi" | "last_seen";
type Tab = "aps" | "clients" | "graph";

export default function MapPage() {
  const [aps, setAPs] = useState<APInfo[]>([]);
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [tab, setTab] = useState<Tab>("aps");
  const [apFilter, setApFilter] = useState("");
  const [apSortBy, setApSortBy] = useState<SortKey>("last_seen");
  const [clientFilter, setClientFilter] = useState("");
  const [clientSortBy, setClientSortBy] = useState<SortKey>("last_seen");

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
    if (apFilter) {
      const f = apFilter.toLowerCase();
      result = result.filter(
        (a) =>
          a.ssid.toLowerCase().includes(f) ||
          a.bssid.toLowerCase().includes(f),
      );
    }
    return [...result].sort((a, b) => {
      switch (apSortBy) {
        case "channel":
          return a.channel - b.channel;
        case "rssi":
          return b.rssi - a.rssi;
        case "last_seen":
        default:
          return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      }
    });
  }, [aps, apFilter, apSortBy]);

  const filteredClients = useMemo(() => {
    let result = clients;
    if (clientFilter) {
      const f = clientFilter.toLowerCase();
      result = result.filter(
        (c) =>
          c.mac.toLowerCase().includes(f) ||
          (c.ssid ?? "").toLowerCase().includes(f) ||
          (c.bssid ?? "").toLowerCase().includes(f),
      );
    }
    return [...result].sort((a, b) => {
      switch (clientSortBy) {
        case "channel":
          return a.channel - b.channel;
        case "rssi":
          return b.rssi - a.rssi;
        case "last_seen":
        default:
          return new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      }
    });
  }, [clients, clientFilter, clientSortBy]);

  // Active clients: seen in data frames or associated. Excludes probe-only
  // MACs (randomized addresses) that have never sent data or associated.
  const activeClientCount = useMemo(
    () => clients.filter((c) => c.frame_count > 0 || c.associated).length,
    [clients],
  );

  // Drill-down from an AP row into the Clients tab pre-filtered by the AP's
  // BSSID. The client filter input matches BSSID substrings, so passing the
  // full BSSID isolates clients seen on that AP.
  const handleAPRowClick = useCallback((rowIndex: number) => {
    const ap = filteredAPs[rowIndex];
    if (!ap) return;
    setClientFilter(ap.bssid);
    setTab("clients");
  }, [filteredAPs]);

  // Same drill-down semantics, but invoked from a graph node click where we
  // already know the BSSID directly.
  const handleAPGraphClick = useCallback((bssid: string) => {
    setClientFilter(bssid);
    setTab("clients");
  }, []);

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Environment Map</h1>
      <div className="grid gap-4 grid-cols-3">
        <Stat label="Access Points" value={aps.length} />
        <Stat label="Clients" value={clients.length} />
        <Stat label="Associated" value={clients.filter((c) => c.associated).length} />
      </div>

      <div className="mt-4 flex gap-1 border-b border-border">
        <TabButton
          active={tab === "aps"}
          onClick={() => setTab("aps")}
          label="Access Points"
          count={aps.length}
        />
        <TabButton
          active={tab === "clients"}
          onClick={() => setTab("clients")}
          label="Clients"
          count={activeClientCount}
        />
        <TabButton
          active={tab === "graph"}
          onClick={() => setTab("graph")}
          label="Graph"
          count={aps.length + activeClientCount}
        />
      </div>

      {tab === "aps" && (
        <>
          <div className="card mt-4 flex gap-3 items-center">
            <input
              className="input min-w-[14rem]"
              placeholder="Search SSID or BSSID…"
              value={apFilter}
              onChange={(e) => setApFilter(e.target.value)}
            />
            {apFilter && (
              <button className="btn" onClick={() => setApFilter("")}>
                Clear
              </button>
            )}
            <label className="stat-label">Sort:</label>
            <select
              className="input"
              value={apSortBy}
              onChange={(e) => setApSortBy(e.target.value as SortKey)}
            >
              <option value="last_seen">Last Seen</option>
              <option value="channel">Channel</option>
              <option value="rssi">RSSI</option>
            </select>
          </div>

          <section className="card">
            <Table
              columns={[
                { header: "BSSID" },
                { header: "SSID", className: COL_TRUNCATE },
                { header: "Channel" },
                { header: "RSSI" },
                { header: "Beacons" },
                { header: "Last Seen" },
              ]}
              rows={filteredAPs.map((a) => [
                <span className="mono">{a.bssid}</span>,
                a.hidden ? <span className="text-slate-500">&lt;hidden&gt;</span> : a.ssid,
                a.channel,
                `${a.rssi} dBm`,
                a.beacon_count,
                new Date(a.last_seen).toLocaleString(),
              ])}
              onRowClick={handleAPRowClick}
              rowTitle="Show clients on this AP"
            />
          </section>
        </>
      )}

      {tab === "clients" && (
        <>
          <div className="card mt-4 flex gap-3 items-center">
            <input
              className="input min-w-[14rem]"
              placeholder="Search MAC, BSSID, or SSID…"
              value={clientFilter}
              onChange={(e) => setClientFilter(e.target.value)}
            />
            {clientFilter && (
              <button className="btn" onClick={() => setClientFilter("")}>
                Clear
              </button>
            )}
            <label className="stat-label">Sort:</label>
            <select
              className="input"
              value={clientSortBy}
              onChange={(e) => setClientSortBy(e.target.value as SortKey)}
            >
              <option value="last_seen">Last Seen</option>
              <option value="channel">Channel</option>
              <option value="rssi">RSSI</option>
            </select>
          </div>

          <section className="card">
            <Table
              columns={[
                { header: "MAC" },
                { header: "Associated" },
                { header: "BSSID" },
                { header: "SSID", className: COL_TRUNCATE },
                { header: "Channel" },
                { header: "RSSI" },
                { header: "Frames" },
                { header: "Last Seen" },
              ]}
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
        </>
      )}

      {tab === "graph" && (
        <EnvironmentGraph
          aps={aps}
          clients={clients}
          onAPClick={handleAPGraphClick}
        />
      )}
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

function TabButton({
  active,
  onClick,
  label,
  count,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors focus:outline-none ${
        active
          ? "border-mono-yellow text-fg"
          : "border-transparent text-muted hover:text-fg"
      }`}
    >
      {label} <span className="text-muted">({count})</span>
    </button>
  );
}

type TableColumn = {
  header: string;
  // Optional Tailwind classes applied to both <th> and <td> for this column.
  // Default behaviour (no className) keeps cells on a single line and shrinks
  // them to fit content width.
  className?: string;
};

// Default behaviour for fit-to-content columns: keep the text on a single
// line. Without an explicit width, `table-layout: auto` will size the column
// to its max-content width (which equals the nowrap text width).
const COL_FIT = "whitespace-nowrap";
// Stretch column: claims all remaining width and truncates overflow with an
// ellipsis. `max-w-0` is the canonical trick that makes `text-overflow:
// ellipsis` work inside an auto-layout table cell.
const COL_TRUNCATE = "w-full max-w-0 overflow-hidden text-ellipsis whitespace-nowrap";

function Table({
  columns,
  rows,
  onRowClick,
  rowTitle,
}: {
  columns: TableColumn[];
  rows: React.ReactNode[][];
  onRowClick?: (rowIndex: number) => void;
  rowTitle?: string;
}) {
  if (rows.length === 0) {
    return <div className="text-slate-500 text-center py-6">No data.</div>;
  }
  const clickable = !!onRowClick;
  return (
    <table className="w-full">
      <thead>
        <tr>
          {columns.map((col) => (
            <th
              key={col.header}
              className={`text-left py-2 px-3 stat-label border-b border-border ${col.className ?? COL_FIT}`}
            >
              {col.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((cells, i) => (
          <tr
            key={i}
            className={`hover:bg-sky-500/5 ${clickable ? "cursor-pointer" : ""}`}
            onClick={clickable ? () => onRowClick!(i) : undefined}
            title={clickable ? rowTitle : undefined}
          >
            {cells.map((c, j) => (
              <td
                key={j}
                className={`py-2 px-3 border-b border-border ${columns[j]?.className ?? COL_FIT}`}
              >
                {c}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
