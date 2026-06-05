// Thin fetch wrapper that knows about the same-origin /api/* surface and
// rethrows non-2xx responses with the problem+json detail when present.

let onUnauthorized: (() => void) | null = null;
export function setOnUnauthorized(cb: (() => void) | null) {
  onUnauthorized = cb;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
}

export interface APInfo {
  bssid: string;
  ssid: string;
  hidden: boolean;
  channel: number;
  rssi: number;
  beacon_count: number;
  first_seen: string;
  last_seen: string;
}

export interface ClientInfo {
  mac: string;
  bssid?: string;
  ssid?: string;
  channel: number;
  rssi: number;
  associated: boolean;
  frame_count: number;
  first_seen: string;
  last_seen: string;
  probe_ssids?: string[];
}

export interface SecurityEvent {
  timestamp: string;
  event_type: string;
  severity: "info" | "warning" | "critical";
  src_mac?: string;
  dst_mac?: string;
  bssid?: string;
  ssid?: string;
  channel: number;
  rssi: number;
  description?: string;
}

export interface StatusResponse {
  version: string;
  commit: string;
  build_date: string;
  started_at: string;
  uptime_seconds: number;
  monitor_interface: string;
  current_channel: number;
  channel_hopping: boolean;
  capabilities: Record<string, unknown>;
  platform_limitations: string[];
  stats: { aps: number; clients: number; events_total: number; events_24h: number };
  detection: { enabled: boolean; rules: number; dedup_window_ns: number };
  state: { enabled: boolean; ttl_ns: number; sweep_interval_ns: number };
  storage: { enabled: boolean };
  auth: { enabled: boolean };
  subscribers: { sse: number };
}

export interface WhitelistEntry {
  mac: string;
  ssid?: string;
  comment?: string;
  source: string;
  created_at: string;
}

export interface BlacklistEntry {
  mac: string;
  reason?: string;
  comment?: string;
  created_at: string;
}

export interface StatsResponse {
  window_seconds: number;
  by_type: { key: string; count: number }[];
  by_severity: { key: string; count: number }[];
  per_hour: { hour_start: string; count: number }[];
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(opts.headers ?? {}) },
    ...opts,
  });
  if (!res.ok) {
    if (res.status === 401) {
      onUnauthorized?.();
    }
    let detail: string = res.statusText;
    try {
      const j = await res.json();
      if (j && typeof j === "object" && "detail" in j && j.detail) detail = String(j.detail);
    } catch {}
    const err = new Error(detail) as Error & { status?: number };
    err.status = res.status;
    throw err;
  }
  if (res.status === 204) return undefined as unknown as T;
  return (await res.json()) as T;
}

export const api = {
  status: () => request<StatusResponse>("/api/status"),
  aps: () => request<ListResponse<APInfo>>("/api/aps"),
  clients: () => request<ListResponse<ClientInfo>>("/api/clients"),
  events: (q: string = "") => request<ListResponse<SecurityEvent>>("/api/events" + (q ? `?${q}` : "")),
  stats: (windowSeconds = 86400) => request<StatsResponse>(`/api/stats?window_seconds=${windowSeconds}`),
  whitelist: () => request<ListResponse<WhitelistEntry>>("/api/whitelist"),
  addWhitelist: (b: { mac: string; ssid?: string; comment?: string }) =>
    request<WhitelistEntry>("/api/whitelist", { method: "POST", body: JSON.stringify(b) }),
  delWhitelist: (mac: string) =>
    request<void>(`/api/whitelist/${encodeURIComponent(mac)}`, { method: "DELETE" }),
  blacklist: () => request<ListResponse<BlacklistEntry>>("/api/blacklist"),
  addBlacklist: (b: { mac: string; reason?: string; comment?: string }) =>
    request<BlacklistEntry>("/api/blacklist", { method: "POST", body: JSON.stringify(b) }),
  delBlacklist: (mac: string) =>
    request<void>(`/api/blacklist/${encodeURIComponent(mac)}`, { method: "DELETE" }),
  config: () => request<unknown>("/api/config"),
  putConfig: (b: Record<string, unknown>) =>
    request<unknown>("/api/config", { method: "PUT", body: JSON.stringify(b) }),
  login: (username: string, password: string) =>
    request<{ role: string; expires_at: string }>("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<void>("/api/logout", { method: "POST" }),
};
