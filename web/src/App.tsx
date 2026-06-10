import { Navigate, NavLink, Route, Routes } from "react-router-dom";

import { useAuth } from "./auth";
import Login from "./pages/Login";
import MapPage from "./pages/Map";
import EventsPage from "./pages/Events";
import StatsPage from "./pages/Stats";
import SettingsPage from "./pages/Settings";
import StatusPage from "./pages/Status";

const TABS: { to: string; label: string }[] = [
  { to: "/map", label: "Map" },
  { to: "/events", label: "Events" },
  { to: "/stats", label: "Stats" },
  { to: "/settings", label: "Settings" },
  { to: "/status", label: "Status" },
];

export default function App() {
  const { role, authChecked, authRequired, logout } = useAuth();

  if (!authChecked) {
    return <div className="flex items-center justify-center min-h-screen text-slate-400">Loading…</div>;
  }
  if (authRequired && !role) {
    return <Login />;
  }

  return (
    <div>
      <header className="bg-bg2 border-b border-border px-6 py-3 flex items-center gap-4">
        <div className="font-bold text-accent">🌊 Tobimaru</div>
        <nav className="flex gap-2 flex-1">
          {TABS.map((t) => (
            <NavLink
              key={t.to}
              to={t.to}
              className={({ isActive }) =>
                isActive ? "nav-link nav-link-active" : "nav-link"
              }
            >
              {t.label}
            </NavLink>
          ))}
        </nav>
        <div className="flex items-center gap-3 text-slate-400">
          {role && <span className="pill-muted">{role}</span>}
          {authRequired && (
            <button className="btn" onClick={logout}>
              Logout
            </button>
          )}
        </div>
      </header>
      <main className="px-6 py-6 max-w-[1280px] mx-auto">
        <Routes>
          <Route path="/" element={<Navigate to="/map" replace />} />
          <Route path="/map" element={<MapPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/stats" element={<StatsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="*" element={<Navigate to="/map" replace />} />
        </Routes>
      </main>
    </div>
  );
}
