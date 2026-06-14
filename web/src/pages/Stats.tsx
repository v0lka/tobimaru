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

// Severity colors are pulled from the Monokai Pro Classic palette so the
// charts share the same hues used by status pills throughout the dashboard.
const SEV_COLORS: Record<string, string> = {
  info: "#78DCE8",    // mono.blue
  warning: "#FFD866", // mono.yellow
  critical: "#FF6188", // mono.red
};

// Shared chart styling tokens (Monokai Pro Classic).
const CHART_GRID = "#403E41"; // bg3
const CHART_AXIS = "#939293"; // muted
const CHART_TOOLTIP_STYLE = {
  background: "#221F22", // bg2
  border: "1px solid #5B595C", // border
  color: "#FCFCFA", // fg
};
const CHART_BAR_PRIMARY = "#FFD866"; // mono.yellow (signature accent)
const CHART_BAR_SECONDARY = "#AB9DF2"; // mono.purple
const CHART_FALLBACK = "#727072"; // comment

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
      <p className="text-muted mb-4">
        Window: last {Math.round(stats.window_seconds / 3600)} hours.
      </p>

      <div className="card">
        <h2 className="stat-label mb-2">Events per hour</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={perHourFmt}>
            <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
            <XAxis dataKey="label" stroke={CHART_AXIS} />
            <YAxis stroke={CHART_AXIS} allowDecimals={false} />
            <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
            <Bar dataKey="count" fill={CHART_BAR_PRIMARY} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2 className="stat-label mb-2">By event type</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={stats.by_type} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
            <XAxis type="number" stroke={CHART_AXIS} allowDecimals={false} />
            <YAxis type="category" dataKey="key" stroke={CHART_AXIS} width={140} />
            <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
            <Bar dataKey="count" fill={CHART_BAR_SECONDARY} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2 className="stat-label mb-2">By severity</h2>
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie data={stats.by_severity} dataKey="count" nameKey="key" outerRadius={90} label>
              {stats.by_severity.map((entry) => (
                <Cell key={entry.key} fill={SEV_COLORS[entry.key] ?? CHART_FALLBACK} />
              ))}
            </Pie>
            <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
