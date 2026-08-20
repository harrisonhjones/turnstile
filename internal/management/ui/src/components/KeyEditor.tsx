import { useState } from "react";
import {
  IonButton,
  IonButtons,
  IonCheckbox,
  IonContent,
  IonHeader,
  IonInput,
  IonItem,
  IonLabel,
  IonModal,
  IonNote,
  IonText,
  IonTitle,
  IonToolbar,
} from "@ionic/react";
import { API, APIError } from "../api";
import type { CreateKeyRequest, Key, UpdateKeyRequest } from "../types";
import StatementsEditor, {
  emptyDraft,
  fromStatements,
  toStatements,
  type DraftStatement,
} from "./StatementsEditor";
import PerActionLimitsEditor, {
  emptyPerActionLimits,
  fromPerActionLimits,
  toPerActionLimits,
  type DraftPerActionLimits,
} from "./PerActionLimitsEditor";

// toLocalInput converts an RFC3339 timestamp to a value for datetime-local.
function toLocalInput(ts?: string): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "";
  // datetime-local wants local time without the trailing Z/offset.
  const off = d.getTimezoneOffset() * 60000;
  return new Date(d.getTime() - off).toISOString().slice(0, 16);
}

interface Props {
  isOpen: boolean;
  existing?: Key; // undefined = create
  onClose: () => void;
  onSaved: (key: Key) => void;
}

// KeyEditor is a modal form for creating or editing an API key.
export default function KeyEditor({ isOpen, existing, onClose, onSaved }: Props) {
  const editing = !!existing;
  const [name, setName] = useState(existing?.name ?? "");
  const [note, setNote] = useState(existing?.note ?? "");
  const [disabled, setDisabled] = useState(existing?.disabled ?? false);
  const [expiresLocal, setExpiresLocal] = useState(toLocalInput(existing?.expiresAt));
  const [statements, setStatements] = useState<DraftStatement[]>(
    existing ? fromStatements(existing.statements) : [emptyDraft()],
  );
  const [rateLimit, setRateLimit] = useState<DraftPerActionLimits>(
    existing ? fromPerActionLimits(existing.rateLimits) : emptyPerActionLimits(),
  );
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError("");
    const stmts = toStatements(statements);
    if (stmts === null) {
      setError("Each statement needs at least one action and one resource.");
      return;
    }
    if (stmts.length === 0) {
      setError("At least one statement is required.");
      return;
    }
    const limits = toPerActionLimits(rateLimit);
    if (limits === null) {
      setError("Rate limits must be non-negative numbers.");
      return;
    }
    const expiresAt = expiresLocal ? new Date(expiresLocal).toISOString() : "";

    setBusy(true);
    try {
      let saved: Key;
      if (editing) {
        const req: UpdateKeyRequest = {
          id: existing!.id,
          name,
          note,
          disabled,
          statements: { statements: stmts },
        };
        // rate_limits is a presence-less map: send it to replace, or
        // clearRateLimits to remove all overrides.
        if (limits) req.rateLimits = limits;
        else req.clearRateLimits = true;
        if (expiresAt) req.expiresAt = expiresAt;
        else req.clearExpiry = true;
        saved = await API.updateKey(req);
      } else {
        const req: CreateKeyRequest = {
          name,
          note: note || undefined,
          disabled,
          statements: stmts,
          rateLimits: limits,
        };
        if (expiresAt) req.expiresAt = expiresAt;
        saved = await API.createKey(req);
      }
      onSaved(saved);
    } catch (e) {
      setError(e instanceof APIError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <IonModal isOpen={isOpen} onDidDismiss={onClose}>
      <IonHeader>
        <IonToolbar>
          <IonTitle>{editing ? "Edit key" : "Create key"}</IonTitle>
          <IonButtons slot="end">
            <IonButton onClick={onClose}>Cancel</IonButton>
          </IonButtons>
        </IonToolbar>
      </IonHeader>
      <IonContent className="ion-padding">
        <IonInput
          label="Name"
          labelPlacement="stacked"
          value={name}
          onIonInput={(e) => setName(e.detail.value ?? "")}
        />
        <IonInput
          label="Note"
          labelPlacement="stacked"
          value={note}
          onIonInput={(e) => setNote(e.detail.value ?? "")}
        />
        <IonInput
          label="Expires at (optional)"
          labelPlacement="stacked"
          type="datetime-local"
          value={expiresLocal}
          onIonInput={(e) => setExpiresLocal(e.detail.value ?? "")}
        />
        <IonItem lines="none">
          <IonCheckbox checked={disabled} onIonChange={(e) => setDisabled(e.detail.checked)}>
            Disabled
          </IonCheckbox>
        </IonItem>

        <IonLabel className="ion-margin-top">
          <h3>Statements</h3>
        </IonLabel>
        <IonNote className="muted">
          Actions and resources are opaque, service-namespaced strings; a single trailing * is a
          wildcard. Deny wins, then first allow, else deny.
        </IonNote>
        <StatementsEditor drafts={statements} onChange={setStatements} />

        <IonLabel className="ion-margin-top">
          <h3>Rate-limit overrides (optional)</h3>
        </IonLabel>
        <IonNote className="muted">
          Per-action overrides of the instance per-key defaults for this key. Leave empty to
          inherit.
        </IonNote>
        <PerActionLimitsEditor value={rateLimit} onChange={setRateLimit} />

        {error && (
          <IonText color="danger">
            <p>{error}</p>
          </IonText>
        )}
        <IonButton
          expand="block"
          className="ion-margin-top"
          onClick={submit}
          disabled={busy || !name.trim()}
        >
          {busy ? "Saving…" : editing ? "Save changes" : "Create key"}
        </IonButton>
      </IonContent>
    </IonModal>
  );
}
