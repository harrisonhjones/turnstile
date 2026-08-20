import { IonButton, IonIcon, IonInput, IonLabel, IonNote } from "@ionic/react";
import { addOutline, trashOutline } from "ionicons/icons";
import type { Limit, PerActionLimits } from "../types";
import { parseLimit } from "../util";

// Draft form for a key's per-action rate-limit overrides: a list of rows, all as
// strings until submit. Unlike the global policy's RateLimitConfig there is no
// blanket default — a key can only override specific actions.
export type DraftPerActionLimits = { action: string; perMinute: string; burst: string }[];

export function emptyPerActionLimits(): DraftPerActionLimits {
  return [];
}

export function fromPerActionLimits(m?: PerActionLimits): DraftPerActionLimits {
  return Object.entries(m ?? {}).map(([action, l]) => ({
    action,
    perMinute: l.perMinute != null ? String(l.perMinute) : "",
    burst: l.burst != null ? String(l.burst) : "",
  }));
}

// toPerActionLimits converts a draft to the wire map. Returns null on a
// malformed number, or undefined when there are no (non-blank) overrides.
export function toPerActionLimits(d: DraftPerActionLimits): PerActionLimits | undefined | null {
  const out: Record<string, Limit> = {};
  for (const row of d) {
    const action = row.action.trim();
    if (!action) continue;
    const l = parseLimit(row.perMinute, row.burst);
    if (l === null || l === undefined) return null;
    out[action] = l;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// PerActionLimitsEditor edits a key's per-action rate-limit overrides.
export default function PerActionLimitsEditor({
  value,
  onChange,
}: {
  value: DraftPerActionLimits;
  onChange: (d: DraftPerActionLimits) => void;
}) {
  const setRow = (i: number, patch: Partial<DraftPerActionLimits[number]>) =>
    onChange(value.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addRow = () => onChange([...value, { action: "", perMinute: "", burst: "" }]);
  const removeRow = (i: number) => onChange(value.filter((_, j) => j !== i));

  return (
    <div className="editor-row">
      <IonNote className="muted"> requests/minute; blank = unlimited</IonNote>
      {value.map((r, i) => (
        <div style={{ display: "flex", gap: 8, alignItems: "flex-end" }} key={i}>
          <IonInput
            label="Action"
            labelPlacement="stacked"
            placeholder="photos:getAlbum"
            value={r.action}
            onIonInput={(e) => setRow(i, { action: e.detail.value ?? "" })}
          />
          <IonInput
            label="/min"
            labelPlacement="stacked"
            type="number"
            value={r.perMinute}
            onIonInput={(e) => setRow(i, { perMinute: e.detail.value ?? "" })}
          />
          <IonInput
            label="burst"
            labelPlacement="stacked"
            type="number"
            value={r.burst}
            onIonInput={(e) => setRow(i, { burst: e.detail.value ?? "" })}
          />
          <IonButton fill="clear" color="danger" onClick={() => removeRow(i)}>
            <IonIcon slot="icon-only" icon={trashOutline} />
          </IonButton>
        </div>
      ))}
      {value.length === 0 && (
        <IonLabel className="muted">No overrides — inherits the instance per-key defaults.</IonLabel>
      )}
      <IonButton fill="outline" size="small" onClick={addRow}>
        <IonIcon slot="start" icon={addOutline} />
        Add per-action limit
      </IonButton>
    </div>
  );
}
