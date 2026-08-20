import { useCallback, useEffect, useState } from "react";
import {
  IonAlert,
  IonBadge,
  IonButton,
  IonButtons,
  IonCard,
  IonCardContent,
  IonCardHeader,
  IonCardSubtitle,
  IonCardTitle,
  IonContent,
  IonFab,
  IonFabButton,
  IonIcon,
  IonItem,
  IonLabel,
  IonModal,
  IonNote,
  IonPage,
  IonRefresher,
  IonRefresherContent,
  IonSpinner,
  IonText,
  IonToggle,
  IonToolbar,
} from "@ionic/react";
import { add, copyOutline } from "ionicons/icons";
import { API, APIError } from "../api";
import type { Key } from "../types";
import { fmtLimit, fmtTime } from "../util";
import AppHeader from "../components/AppHeader";
import KeyEditor from "../components/KeyEditor";

export default function Keys() {
  const [keys, setKeys] = useState<Key[]>([]);
  const [includeDisabled, setIncludeDisabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Key | undefined>();
  const [newToken, setNewToken] = useState<Key | null>(null); // shows plaintext once
  const [confirmDelete, setConfirmDelete] = useState<Key | null>(null);

  const load = useCallback(async () => {
    setError("");
    try {
      const resp = await API.listKeys(includeDisabled);
      setKeys(resp.keys ?? []);
    } catch (e) {
      setError(e instanceof APIError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [includeDisabled]);

  useEffect(() => {
    void load();
  }, [load]);

  const onSaved = (key: Key) => {
    setEditorOpen(false);
    // A freshly created key carries its plaintext token exactly once.
    if (key.plaintextToken) setNewToken(key);
    setEditing(undefined);
    void load();
  };

  const doDelete = async (key: Key) => {
    try {
      await API.deleteKey(key.id);
      void load();
    } catch (e) {
      setError(e instanceof APIError ? e.message : String(e));
    }
  };

  return (
    <IonPage>
      <AppHeader title="Keys" />
      <IonContent className="ion-padding">
        <IonRefresher slot="fixed" onIonRefresh={(e) => load().then(() => e.detail.complete())}>
          <IonRefresherContent />
        </IonRefresher>

        <IonToolbar>
          <IonItem lines="none">
            <IonToggle
              checked={includeDisabled}
              onIonChange={(e) => setIncludeDisabled(e.detail.checked)}
            >
              Include disabled
            </IonToggle>
          </IonItem>
        </IonToolbar>

        {error && (
          <IonText color="danger">
            <p>{error}</p>
          </IonText>
        )}
        {loading ? (
          <div className="ion-text-center">
            <IonSpinner />
          </div>
        ) : keys.length === 0 ? (
          <IonNote className="muted">No keys yet. Create one with the + button.</IonNote>
        ) : (
          keys.map((k) => (
            <KeyCard
              key={k.id}
              k={k}
              onEdit={() => {
                setEditing(k);
                setEditorOpen(true);
              }}
              onDelete={() => setConfirmDelete(k)}
            />
          ))
        )}

        <IonFab slot="fixed" vertical="bottom" horizontal="end">
          <IonFabButton
            onClick={() => {
              setEditing(undefined);
              setEditorOpen(true);
            }}
          >
            <IonIcon icon={add} />
          </IonFabButton>
        </IonFab>

        {editorOpen && (
          <KeyEditor
            isOpen={editorOpen}
            existing={editing}
            onClose={() => {
              setEditorOpen(false);
              setEditing(undefined);
            }}
            onSaved={onSaved}
          />
        )}

        <TokenRevealModal keyWithToken={newToken} onClose={() => setNewToken(null)} />

        <IonAlert
          isOpen={!!confirmDelete}
          header="Delete key?"
          message={`Permanently delete "${confirmDelete?.name}"? Any client using its token will be denied.`}
          buttons={[
            { text: "Cancel", role: "cancel" },
            {
              text: "Delete",
              role: "destructive",
              handler: () => {
                if (confirmDelete) void doDelete(confirmDelete);
              },
            },
          ]}
          onDidDismiss={() => setConfirmDelete(null)}
        />
      </IonContent>
    </IonPage>
  );
}

function KeyCard({ k, onEdit, onDelete }: { k: Key; onEdit: () => void; onDelete: () => void }) {
  return (
    <IonCard>
      <IonCardHeader>
        <IonCardTitle>
          {k.name} {k.disabled && <IonBadge color="medium">disabled</IonBadge>}{" "}
          {k.ownerNamespace && <IonBadge color="tertiary">{k.ownerNamespace}</IonBadge>}
        </IonCardTitle>
        <IonCardSubtitle className="mono">{k.id}</IonCardSubtitle>
      </IonCardHeader>
      <IonCardContent>
        {k.note && <p>{k.note}</p>}
        <p className="muted">
          created {fmtTime(k.createdAt)} · last used {fmtTime(k.lastUsedAt)}
          {k.expiresAt ? ` · expires ${fmtTime(k.expiresAt)}` : ""}
        </p>

        <IonLabel>
          <strong>Statements</strong>
        </IonLabel>
        {(k.statements ?? []).map((s, i) => (
          <div className="mono" key={i}>
            {s.effect === "EFFECT_DENY" ? "deny" : "allow"} {(s.actions ?? []).join(", ")} on{" "}
            {(s.resources ?? []).join(", ")}
          </div>
        ))}

        {(k.rateLimits?.default || k.rateLimits?.perAction) && (
          <>
            <IonLabel className="ion-margin-top">
              <strong>Rate-limit overrides</strong>
            </IonLabel>
            {k.rateLimits?.default && (
              <div className="mono">default: {fmtLimit(k.rateLimits.default)}</div>
            )}
            {Object.entries(k.rateLimits?.perAction ?? {}).map(([a, l]) => (
              <div className="mono" key={a}>
                {a}: {fmtLimit(l)}
              </div>
            ))}
          </>
        )}

        <IonButtons className="ion-margin-top">
          <IonButton fill="outline" size="small" onClick={onEdit}>
            Edit
          </IonButton>
          <IonButton fill="outline" size="small" color="danger" onClick={onDelete}>
            Delete
          </IonButton>
        </IonButtons>
      </IonCardContent>
    </IonCard>
  );
}

// TokenRevealModal shows a freshly-created key's plaintext token exactly once.
function TokenRevealModal({
  keyWithToken,
  onClose,
}: {
  keyWithToken: Key | null;
  onClose: () => void;
}) {
  const copy = () => {
    if (keyWithToken?.plaintextToken) navigator.clipboard?.writeText(keyWithToken.plaintextToken);
  };
  return (
    <IonModal isOpen={!!keyWithToken} onDidDismiss={onClose}>
      <IonContent className="ion-padding">
        <h2>Key created</h2>
        <IonText color="warning">
          <p>
            Copy this token now — it is shown only once and cannot be recovered. Only its hash is
            stored.
          </p>
        </IonText>
        <div className="token-reveal">{keyWithToken?.plaintextToken}</div>
        <IonButton onClick={copy}>
          <IonIcon slot="start" icon={copyOutline} />
          Copy
        </IonButton>
        <IonButton fill="outline" onClick={onClose}>
          Done
        </IonButton>
      </IonContent>
    </IonModal>
  );
}
