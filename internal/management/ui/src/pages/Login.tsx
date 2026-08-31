import { useState } from "react";
import {
  IonButton,
  IonCard,
  IonCardContent,
  IonCardHeader,
  IonCardTitle,
  IonContent,
  IonInput,
  IonNote,
  IonPage,
  IonText,
} from "@ionic/react";
import { useAuth } from "../auth";

// Login accepts a management key (a tsk_… token whose policy allows turnstile:*
// actions — e.g. the bootstrap key printed once on first server start) and
// validates it against a management RPC.
export default function Login() {
  const { signIn } = useAuth();
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError("");
    setBusy(true);
    try {
      await signIn(token.trim());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <IonPage>
      <IonContent className="ion-padding">
        <IonCard className="login-card">
          <IonCardHeader>
            <IonCardTitle>Turnstile</IonCardTitle>
            <IonNote>Sign in with a management key to manage keys, policy, and audit.</IonNote>
          </IonCardHeader>
          <IonCardContent>
            <IonInput
              label="Management key"
              labelPlacement="stacked"
              type="password"
              placeholder="tsk_…"
              value={token}
              onIonInput={(e) => setToken(e.detail.value ?? "")}
              onKeyDown={(e) => e.key === "Enter" && submit()}
            />
            {error && (
              <IonText color="danger">
                <p>{error}</p>
              </IonText>
            )}
            <IonButton
              expand="block"
              className="ion-margin-top"
              onClick={submit}
              disabled={busy || !token.trim()}
            >
              {busy ? "Signing in…" : "Sign in"}
            </IonButton>
            <IonNote className="muted">
              The bootstrap key's token is logged once on first start. Locked out? Restart with
              -bootstrap (or TURNSTILE_BOOTSTRAP=true) to mint a fresh full-admin key.
            </IonNote>
          </IonCardContent>
        </IonCard>
      </IonContent>
    </IonPage>
  );
}
