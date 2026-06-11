import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import logoUrl from "../assets/logo-128.png";

export default function Login() {
  const { login, loginErr } = useAuth();
  const navigate = useNavigate();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await login(u, p);
      navigate("/map");
    } catch {
      /* error already in loginErr */
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="bg-bg2 border border-border rounded-lg p-8 w-[360px] shadow-[0_4px_24px_rgba(0,0,0,0.45)]">
        <div className="flex flex-col items-center mb-6">
          <img
            src={logoUrl}
            alt="Tobimaru"
            width={64}
            height={64}
            className="w-16 h-16 mb-3 rounded-md"
          />
          <h1 className="text-xl font-bold tracking-wide">
            Tobi<span className="text-mono-yellow">maru</span>
          </h1>
        </div>
        <form onSubmit={handleSubmit}>
          <label className="block stat-label mt-3 mb-1">Username</label>
          <input
            className="input w-full"
            type="text"
            autoComplete="username"
            value={u}
            onChange={(e) => setU(e.target.value)}
            required
          />
          <label className="block stat-label mt-3 mb-1">Password</label>
          <input
            className="input w-full"
            type="password"
            autoComplete="current-password"
            value={p}
            onChange={(e) => setP(e.target.value)}
            required
          />
          <div className="text-mono-red mt-2 min-h-[1.5em]">{loginErr}</div>
          <button
            type="submit"
            className="btn btn-primary w-full mt-4"
            disabled={submitting}
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
