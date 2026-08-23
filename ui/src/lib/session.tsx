import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { ApiError, endpoints, setCsrfToken, type User } from "./api";

interface SessionContextValue {
  user: User | null;
  /** Undefined until the first `/api/auth/me` has resolved. */
  ready: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  // Restore the session on load: the cookie is HttpOnly, so the only way to
  // know whether we are signed in is to ask.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const session = await endpoints.me();
        if (cancelled) return;
        setCsrfToken(session.csrf_token);
        setUser(session.user);
      } catch (error) {
        if (!(error instanceof ApiError) || !error.isUnauthenticated) {
          console.error("session restore failed", error);
        }
      } finally {
        if (!cancelled) setReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const signIn = useCallback(async (username: string, password: string) => {
    const session = await endpoints.login(username, password);
    setCsrfToken(session.csrf_token);
    setUser(session.user);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await endpoints.logout();
    } finally {
      // Whatever the server said, this browser is done with the session.
      setCsrfToken(null);
      setUser(null);
    }
  }, []);

  const value = useMemo(() => ({ user, ready, signIn, signOut }), [user, ready, signIn, signOut]);
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) throw new Error("useSession must be used inside SessionProvider");
  return context;
}
