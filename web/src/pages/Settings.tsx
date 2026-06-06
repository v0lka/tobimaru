import { useCallback, useEffect, useState } from "react";
import { api, type BlacklistEntry, type WhitelistEntry } from "../api";
import { useAuth } from "../auth";
import yaml from "js-yaml";

interface ConfigResponse {
  effective: Record<string, unknown>;
  mutable: {
    log_level: string;
    detection_enabled: boolean;
    detection_dedup_window_ns: number;
  };
}

export default function SettingsPage() {
  const { role } = useAuth();
  const [cfg, setCfg] = useState<ConfigResponse | null>(null);
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([]);
  const [blacklist, setBlacklist] = useState<BlacklistEntry[]>([]);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setError("");
    try {
      const c = (await api.config()) as ConfigResponse;
      setCfg(c);
    } catch (e) {
      setError((e as Error).message);
    }
    try {
      const w = await api.whitelist();
      setWhitelist(w.items);
    } catch {}
    try {
      const b = await api.blacklist();
      setBlacklist(b.items);
    } catch {}
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (!cfg) return <div className="text-slate-500 text-center py-6">Loading…</div>;
  const isAdmin = role === "admin";

  async function patch(body: Record<string, unknown>) {
    try {
      await api.putConfig(body);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Settings</h1>
      {error && <div className="card text-red-400">{error}</div>}

      <section className="card">
        <h2 className="stat-label mb-2">Runtime Settings</h2>
        <p className="text-slate-400 mb-3">
          Mutable values that affect the running daemon. The YAML file on disk is never modified.
        </p>
        <div className="flex gap-3 items-center mb-2">
          <label>Log level:</label>
          <select
            className="input"
            value={cfg.mutable.log_level}
            onChange={(e) => patch({ log_level: e.target.value })}
            disabled={!isAdmin}
          >
            {["debug", "info", "warn", "error"].map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <div className="flex gap-3 items-center mb-2">
          <label>
            <input
              type="checkbox"
              checked={cfg.mutable.detection_enabled}
              onChange={(e) => patch({ detection_enabled: e.target.checked })}
              disabled={!isAdmin}
              className="mr-2"
            />
            Detection enabled
          </label>
        </div>
        <DedupWindowEditor
          currentNs={cfg.mutable.detection_dedup_window_ns}
          disabled={!isAdmin}
          onApply={(v) => patch({ detection_dedup_window: v })}
        />
      </section>

      <ListEditor
        title="Whitelist"
        kind="whitelist"
        items={whitelist}
        admin={isAdmin}
        onAdd={async (mac, comment) => {
          await api.addWhitelist({ mac, comment });
          await refresh();
        }}
        onDelete={async (mac) => {
          await api.delWhitelist(mac);
          await refresh();
        }}
      />

      <ListEditor
        title="Blacklist"
        kind="blacklist"
        items={blacklist}
        admin={isAdmin}
        onAdd={async (mac, reason) => {
          await api.addBlacklist({ mac, reason });
          await refresh();
        }}
        onDelete={async (mac) => {
          await api.delBlacklist(mac);
          await refresh();
        }}
      />

      <section className="card">
        <h2 className="stat-label mb-2">Effective configuration (read-only)</h2>
        <pre className="mono whitespace-pre-wrap max-h-96 overflow-auto">
          {yaml.dump(cfg.effective as Record<string, unknown>, { indent: 2, lineWidth: 120, sortKeys: true })}
        </pre>
      </section>
    </div>
  );
}

function DedupWindowEditor({
  currentNs,
  disabled,
  onApply,
}: {
  currentNs: number;
  disabled: boolean;
  onApply: (v: string) => void;
}) {
  const [v, setV] = useState("");
  return (
    <div className="flex gap-2 items-center">
      <label>Dedup window:</label>
      <input
        className="input"
        placeholder="e.g. 30s"
        value={v}
        onChange={(e) => setV(e.target.value)}
        disabled={disabled}
      />
      <button className="btn btn-primary" onClick={() => v && onApply(v)} disabled={disabled}>
        Apply
      </button>
      <span className="text-slate-400">
        current: {currentNs ? `${Math.round(currentNs / 1e9)}s` : "—"}
      </span>
    </div>
  );
}

interface ListItemBase {
  mac: string;
  created_at: string;
}

function ListEditor<T extends ListItemBase & { ssid?: string; comment?: string; reason?: string; source?: string }>({
  title,
  kind,
  items,
  admin,
  onAdd,
  onDelete,
}: {
  title: string;
  kind: "whitelist" | "blacklist";
  items: T[];
  admin: boolean;
  onAdd: (mac: string, note: string) => Promise<void>;
  onDelete: (mac: string) => Promise<void>;
}) {
  const [mac, setMac] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");

  async function add() {
    setErr("");
    try {
      await onAdd(mac, note);
      setMac("");
      setNote("");
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <section className="card">
      <h2 className="stat-label mb-2">{title}</h2>
      {admin ? (
        <div className="flex gap-2 mb-3 items-center flex-wrap">
          <input
            className="input min-w-[14rem]"
            placeholder="MAC address (aa:bb:cc:dd:ee:ff)"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
          <input
            className="input min-w-[10rem]"
            placeholder={kind === "blacklist" ? "Reason" : "Comment"}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <button className="btn btn-primary" onClick={add}>
            Add
          </button>
          {err && <span className="text-red-400">{err}</span>}
        </div>
      ) : (
        <p className="text-slate-400 mb-2">Admin role required to modify {title.toLowerCase()}.</p>
      )}

      {items.length === 0 ? (
        <div className="text-slate-500 text-center py-6">No entries.</div>
      ) : (
        <table className="w-full">
          <thead>
            <tr>
              {(kind === "blacklist"
                ? ["MAC", "Reason", "Comment", "Created"]
                : ["MAC", "SSID", "Comment", "Source", "Created"]
              ).map((h) => (
                <th key={h} className="text-left py-2 px-3 stat-label border-b border-border">
                  {h}
                </th>
              ))}
              {admin && <th />}
            </tr>
          </thead>
          <tbody>
            {items.map((it) => (
              <tr key={it.mac} className="hover:bg-sky-500/5">
                <td className="py-2 px-3 border-b border-border mono">{it.mac}</td>
                {kind === "blacklist" ? (
                  <>
                    <td className="py-2 px-3 border-b border-border">{it.reason ?? ""}</td>
                    <td className="py-2 px-3 border-b border-border">{it.comment ?? ""}</td>
                  </>
                ) : (
                  <>
                    <td className="py-2 px-3 border-b border-border">{it.ssid ?? ""}</td>
                    <td className="py-2 px-3 border-b border-border">{it.comment ?? ""}</td>
                    <td className="py-2 px-3 border-b border-border">
                      <span className="pill-muted">{it.source ?? ""}</span>
                    </td>
                  </>
                )}
                <td className="py-2 px-3 border-b border-border">
                  {new Date(it.created_at).toLocaleString()}
                </td>
                {admin && (
                  <td className="py-2 px-3 border-b border-border">
                    <button className="btn btn-danger" onClick={() => onDelete(it.mac)}>
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
