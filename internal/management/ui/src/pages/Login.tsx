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

// Login accepts an admin credential (the tsa_… bootstrap token, printed once on
// first server start) and validates it against a management RPC.
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
            <IonNote>Sign in with an admin credential to manage keys, policy, and audit.</IonNote>
          </IonCardHeader>
          <IonCardContent>
            <IonInput
              label="Admin credential"
              labelPlacement="stacked"
              type="password"
              placeholder="tsa_…"
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
              The bootstrap credential is logged once on first start. Delete all admin credentials
              and restart to re-seed one.
            </IonNote>
          </IonCardContent>
        </IonCard>
      </IonContent>
    </IonPage>
  );
}
