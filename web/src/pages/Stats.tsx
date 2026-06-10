import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { api, type StatsResponse } from "../api";

const SEV_COLORS: Record<string, string> = {
  info: "#38bdf8",
  warning: "#f59e0b",
  critical: "#ef4444",
};

export default function StatsPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    api.stats().then((s) => mounted && setStats(s)).catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  if (!stats) {
    return <div className="text-slate-500 text-center py-6">Loading statistics…</div>;
  }

  const perHourFmt = stats.per_hour.map((p) => ({
    ...p,
    label: new Date(p.hour_start).toLocaleTimeString([], { hour: "2-digit" }),
  }));

  return (
    <div>
      <h1 className="text-xl font-semibold mb-4">Statistics</h1>
      <p className="text-slate-400 mb-4">
        Window: last {Math.round(stats.window_seconds / 3600)} hours.
      </p>

      <div className="card">
        <h2 className="stat-label mb-2">Events per hour</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={perHourFmt}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="label" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" allowDecimals={false} />
            <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #475569" }} />
            <Bar dataKey="count" fill="#38bdf8" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2 className="stat-label mb-2">By event type</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={stats.by_type} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
            <YAxis type="category" dataKey="key" stroke="#94a3b8" width={140} />
            <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #475569" }} />
            <Bar dataKey="count" fill="#818cf8" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2 className="stat-label mb-2">By severity</h2>
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie data={stats.by_severity} dataKey="count" nameKey="key" outerRadius={90} label>
              {stats.by_severity.map((entry) => (
                <Cell key={entry.key} fill={SEV_COLORS[entry.key] ?? "#64748b"} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #475569" }} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
