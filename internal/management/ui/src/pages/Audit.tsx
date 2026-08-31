import { useCallback, useEffect, useState } from "react";
import {
  IonButton,
  IonCol,
  IonContent,
  IonGrid,
  IonInput,
  IonItem,
  IonLabel,
  IonList,
  IonNote,
  IonPage,
  IonRow,
  IonSelect,
  IonSelectOption,
  IonSpinner,
  IonText,
} from "@ionic/react";
import { API, APIError } from "../api";
import type { AuditEntry, QueryAuditRequest } from "../types";
import { fmtTime } from "../util";
import AppHeader from "../components/AppHeader";

const PAGE = 50;

interface Filters {
  apiKeyId: string;
  actionPrefix: string;
  decision: string; // "" = any, else a Decision value
  after: string; // datetime-local
  before: string;
}

const emptyFilters: Filters = {
  apiKeyId: "",
  actionPrefix: "",
  decision: "",
  after: "",
  before: "",
};

const DECISIONS = ["ALLOWED", "POLICY_DENIED", "RATE_LIMITED", "UNAUTHENTICATED"] as const;

function toISO(local: string): string | undefined {
  return local ? new Date(local).toISOString() : undefined;
}

export default function Audit() {
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [cursor, setCursor] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // fetchPage loads one page. When reset is true it starts a fresh query;
  // otherwise it appends the next keyset page via the current cursor.
  const fetchPage = useCallback(
    async (reset: boolean) => {
      setError("");
      setLoading(true);
      const req: QueryAuditRequest = {
        apiKeyId: filters.apiKeyId || undefined,
        actionPrefix: filters.actionPrefix || undefined,
        decision: (filters.decision || undefined) as QueryAuditRequest["decision"],
        after: toISO(filters.after),
        before: toISO(filters.before),
        limit: PAGE,
        cursor: reset ? undefined : cursor || undefined,
      };
      try {
        const resp = await API.queryAudit(req);
        const next = resp.entries ?? [];
        setEntries((prev) => (reset ? next : [...prev, ...next]));
        setCursor(resp.nextCursor && resp.nextCursor !== "0" ? resp.nextCursor : "");
      } catch (e) {
        setError(e instanceof APIError ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    },
    [filters, cursor],
  );

  // Initial load.
  useEffect(() => {
    void fetchPage(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const set = (patch: Partial<Filters>) => setFilters((f) => ({ ...f, ...patch }));

  return (
    <IonPage>
      <AppHeader title="Audit" />
      <IonContent className="ion-padding">
        <IonGrid>
          <IonRow>
            <IonCol size="12" sizeMd="4">
              <IonInput
                label="API key id"
                labelPlacement="stacked"
                value={filters.apiKeyId}
                onIonInput={(e) => set({ apiKeyId: e.detail.value ?? "" })}
              />
            </IonCol>
            <IonCol size="12" sizeMd="4">
              <IonInput
                label="Action prefix"
                labelPlacement="stacked"
                placeholder="photos:"
                value={filters.actionPrefix}
                onIonInput={(e) => set({ actionPrefix: e.detail.value ?? "" })}
              />
            </IonCol>
            <IonCol size="12" sizeMd="4">
              <IonSelect
                label="Decision"
                labelPlacement="stacked"
                placeholder="Any"
                value={filters.decision}
                onIonChange={(e) => set({ decision: e.detail.value ?? "" })}
              >
                <IonSelectOption value="">Any</IonSelectOption>
                {DECISIONS.map((d) => (
                  <IonSelectOption key={d} value={d}>
                    {d}
                  </IonSelectOption>
                ))}
              </IonSelect>
            </IonCol>
            <IonCol size="6" sizeMd="4">
              <IonInput
                label="After"
                labelPlacement="stacked"
                type="datetime-local"
                value={filters.after}
                onIonInput={(e) => set({ after: e.detail.value ?? "" })}
              />
            </IonCol>
            <IonCol size="6" sizeMd="4">
              <IonInput
                label="Before"
                labelPlacement="stacked"
                type="datetime-local"
                value={filters.before}
                onIonInput={(e) => set({ before: e.detail.value ?? "" })}
              />
            </IonCol>
            <IonCol size="12" sizeMd="4" className="ion-align-self-end">
              <IonButton expand="block" onClick={() => fetchPage(true)}>
                Apply filters
              </IonButton>
              <IonButton
                expand="block"
                fill="outline"
                onClick={() => {
                  setFilters(emptyFilters);
                  setCursor("");
                }}
              >
                Clear
              </IonButton>
            </IonCol>
          </IonRow>
        </IonGrid>

        {error && (
          <IonText color="danger">
            <p>{error}</p>
          </IonText>
        )}

        <IonList>
          {entries.map((e, i) => (
            <IonItem key={`${e.timestamp}-${i}`} lines="full">
              <IonLabel>
                <h3 className="mono">
                  {e.action || "—"} → {e.decision}
                </h3>
                <p className="muted">
                  {fmtTime(e.timestamp)} · key {e.apiKeyId || "—"}
                </p>
                {e.resource && <p className="mono">resource: {e.resource}</p>}
              </IonLabel>
            </IonItem>
          ))}
        </IonList>

        {loading && (
          <div className="ion-text-center">
            <IonSpinner />
          </div>
        )}
        {!loading && entries.length === 0 && (
          <IonNote className="muted">No audit entries match.</IonNote>
        )}
        {cursor && !loading && (
          <IonButton expand="block" fill="outline" onClick={() => fetchPage(false)}>
            Load more
          </IonButton>
        )}
      </IonContent>
    </IonPage>
  );
}
