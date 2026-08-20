// Auth context: holds the admin sign-in state and exposes sign-in/out. The admin
// credential itself lives in the api module's Auth store (localStorage-mirrored);
// this layer tracks whether we are signed in and drives the login gate. There is
// no dedicated "verify credential" RPC, so a paste is validated lazily by the
// first management call (GetPolicy) during sign-in.
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { API, APIError, Auth } from "./api";

interface AuthState {
  signedIn: boolean;
  loading: boolean;
  signIn: (token: string) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [signedIn, setSignedIn] = useState(false);
  const [loading, setLoading] = useState(true);

  // On startup, treat a stored token as signed-in (it is re-validated by the
  // first real call; a 401 there sends the user back to Login via signOut).
  useEffect(() => {
    setSignedIn(!!Auth.load());
    setLoading(false);
  }, []);

  const signIn = async (token: string) => {
    Auth.set(token);
    try {
      await API.getPolicy(); // validate the credential against a management RPC
      setSignedIn(true);
    } catch (e) {
      Auth.clear();
      if (e instanceof APIError && e.status === 401) {
        throw new Error("That admin credential is not valid.");
      }
      throw e;
    }
  };

  const signOut = () => {
    Auth.clear();
    setSignedIn(false);
  };

  return (
    <AuthContext.Provider value={{ signedIn, loading, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
