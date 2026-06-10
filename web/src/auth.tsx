import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "./api";
import { setOnUnauthorized } from "./api";

export type Role = "admin" | "user" | null;

interface AuthContextValue {
  role: Role;
  authChecked: boolean;
  authRequired: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
  loginErr: string;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [role, setRole] = useState<Role>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authRequired, setAuthRequired] = useState(true);
  const [loginErr, setLoginErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const status = await api.status();
        if (cancelled) return;
        setAuthRequired(!!status.auth?.enabled);
        if (!status.auth?.enabled) {
          setRole("admin");
        } else {
          // Probe whether session cookie is still valid.
          try {
            await api.aps();
            if (!cancelled) setRole("user");
          } catch {
            /* not authenticated */
          }
        }
      } finally {
        if (!cancelled) setAuthChecked(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Register global 401 handler so any failed fetch triggers logout.
  useEffect(() => {
    setOnUnauthorized(() => {
      setRole(null);
    });
    return () => setOnUnauthorized(null);
  }, []);

  const login = useCallback(async (u: string, p: string) => {
    setLoginErr("");
    try {
      const resp = await api.login(u, p);
      setRole(resp.role as Role);
    } catch (e) {
      setLoginErr((e as Error).message || "login failed");
      throw e;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {}
    setRole(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ role, authChecked, authRequired, login, logout, loginErr }),
    [role, authChecked, authRequired, login, logout, loginErr],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
