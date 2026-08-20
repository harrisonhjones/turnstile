import { useEffect, useState } from "react";
import {
  IonButton,
  IonContent,
  IonLabel,
  IonNote,
  IonPage,
  IonSpinner,
  IonText,
} from "@ionic/react";
import { API, APIError } from "../api";
import type { Policy as PolicyMsg, UpdatePolicyRequest } from "../types";
import { fmtTime } from "../util";
import AppHeader from "../components/AppHeader";
import StatementsEditor, {
  fromStatements,
  toStatements,
  type DraftStatement,
} from "../components/StatementsEditor";
import RateLimitEditor, {
  emptyRateLimit,
  fromRateLimit,
  toRateLimit,
  type DraftRateLimit,
} from "../components/RateLimitEditor";

export default function Policy() {
  const [policy, setPolicy] = useState<PolicyMsg | null>(null);
  const [statements, setStatements] = useState<DraftStatement[]>([]);
  const [perKey, setPerKey] = useState<DraftRateLimit>(emptyRateLimit());
  const [serviceWide, setServiceWide] = useState<DraftRateLimit>(emptyRateLimit());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  const hydrate = (p: PolicyMsg) => {
    setPolicy(p);
    setStatements(fromStatements(p.statements));
    setPerKey(fromRateLimit(p.rateLimits?.perKey));
    setServiceWide(fromRateLimit(p.rateLimits?.serviceWide));
  };

  const load = async () => {
    setError("");
    setStatus("");
    try {
      hydrate(await API.getPolicy());
    } catch (e) {
      setError(e instanceof APIError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const save = async () => {
    setError("");
    setStatus("");
    const stmts = toStatements(statements);
    if (stmts === null) {
      setError("Each deny statement needs at least one action and one resource.");
      return;
    }
    const pk = toRateLimit(perKey);
    const sw = toRateLimit(serviceWide);
    if (pk === null || sw === null) {
      setError("Rate limits must be non-negative numbers.");
      return;
    }
    const req: UpdatePolicyRequest = {
      statements: stmts,
      rateLimits: { perKey: pk ?? {}, serviceWide: sw ?? {} },
      expectedVersion: policy?.version ?? "0",
    };
    setBusy(true);
    try {
      hydrate(await API.updatePolicy(req));
      setStatus("Policy updated.");
    } catch (e) {
      if (e instanceof APIError && e.code === "aborted") {
        setError("The policy changed since you loaded it (version conflict). Reload and re-apply.");
      } else {
        setError(e instanceof APIError ? e.message : String(e));
      }
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return (
      <IonPage>
        <AppHeader title="Policy" />
        <IonContent className="ion-padding ion-text-center">
          <IonSpinner />
        </IonContent>
      </IonPage>
    );
  }

  return (
    <IonPage>
      <AppHeader title="Policy" />
      <IonContent className="ion-padding">
        <IonNote className="muted">
          Version {policy?.version} · updated {fmtTime(policy?.updatedAt)} by{" "}
          {policy?.updatedBy || "—"}
        </IonNote>

        <IonLabel className="ion-margin-top">
          <h3>Global deny ceiling</h3>
        </IonLabel>
        <IonText color="medium">
          <p className="muted">
            The global policy is a restriction ceiling evaluated before every key: it may only{" "}
            <strong>deny</strong>. A global allow would be additive to every key, so the server
            rejects allow statements here.
          </p>
        </IonText>
        <StatementsEditor drafts={statements} onChange={setStatements} denyOnly />

        <IonLabel className="ion-margin-top">
          <h3>Rate limits</h3>
        </IonLabel>
        <RateLimitEditor label="Per-key defaults" value={perKey} onChange={setPerKey} />
        <RateLimitEditor label="Service-wide caps" value={serviceWide} onChange={setServiceWide} />

        {error && (
          <IonText color="danger">
            <p>{error}</p>
          </IonText>
        )}
        {status && (
          <IonText color="success">
            <p>{status}</p>
          </IonText>
        )}
        <IonButton expand="block" className="ion-margin-top" onClick={save} disabled={busy}>
          {busy ? "Saving…" : "Save policy"}
        </IonButton>
        <IonButton expand="block" fill="outline" onClick={load} disabled={busy}>
          Reload
        </IonButton>
      </IonContent>
    </IonPage>
  );
}
