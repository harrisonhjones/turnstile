import { IonButton, IonIcon, IonInput, IonLabel, IonNote } from "@ionic/react";
import { addOutline, trashOutline } from "ionicons/icons";
import type { Limit, RateLimitConfig } from "../types";
import { parseLimit } from "../util";

// Draft form for a RateLimitConfig: a default limit plus per-action rows, all as
// strings until submit.
export interface DraftRateLimit {
  defaultPerMinute: string;
  defaultBurst: string;
  perAction: { action: string; perMinute: string; burst: string }[];
}

export function emptyRateLimit(): DraftRateLimit {
  return { defaultPerMinute: "", defaultBurst: "", perAction: [] };
}

export function fromRateLimit(c?: RateLimitConfig): DraftRateLimit {
  return {
    defaultPerMinute: c?.default?.perMinute != null ? String(c.default.perMinute) : "",
    defaultBurst: c?.default?.burst != null ? String(c.default.burst) : "",
    perAction: Object.entries(c?.perAction ?? {}).map(([action, l]) => ({
      action,
      perMinute: l.perMinute != null ? String(l.perMinute) : "",
      burst: l.burst != null ? String(l.burst) : "",
    })),
  };
}

// toRateLimit converts a draft to a RateLimitConfig. Returns null on a malformed
// number. An all-blank draft yields undefined (no overrides).
export function toRateLimit(d: DraftRateLimit): RateLimitConfig | undefined | null {
  const out: RateLimitConfig = {};
  const def = parseLimit(d.defaultPerMinute, d.defaultBurst);
  if (def === null) return null;
  if (def) out.default = def;

  const perAction: Record<string, Limit> = {};
  for (const row of d.perAction) {
    const action = row.action.trim();
    if (!action) continue;
    const l = parseLimit(row.perMinute, row.burst);
    if (l === null || l === undefined) return null;
    perAction[action] = l;
  }
  if (Object.keys(perAction).length > 0) out.perAction = perAction;

  return out.default || out.perAction ? out : undefined;
}

// RateLimitEditor edits a single RateLimitConfig (used for a key's overrides and
// for each side of the global policy's per-key / service-wide limits).
export default function RateLimitEditor({
  label,
  value,
  onChange,
}: {
  label: string;
  value: DraftRateLimit;
  onChange: (d: DraftRateLimit) => void;
}) {
  const setDefault = (patch: Partial<DraftRateLimit>) => onChange({ ...value, ...patch });
  const setRow = (i: number, patch: Partial<DraftRateLimit["perAction"][number]>) =>
    onChange({
      ...value,
      perAction: value.perAction.map((r, j) => (j === i ? { ...r, ...patch } : r)),
    });
  const addRow = () =>
    onChange({
      ...value,
      perAction: [...value.perAction, { action: "", perMinute: "", burst: "" }],
    });
  const removeRow = (i: number) =>
    onChange({ ...value, perAction: value.perAction.filter((_, j) => j !== i) });

  return (
    <div className="editor-row">
      <IonLabel>
        <strong>{label}</strong>
      </IonLabel>
      <IonNote className="muted"> requests/minute; blank = unlimited</IonNote>
      <div style={{ display: "flex", gap: 8 }}>
        <IonInput
          label="Default /min"
          labelPlacement="stacked"
          type="number"
          value={value.defaultPerMinute}
          onIonInput={(e) => setDefault({ defaultPerMinute: e.detail.value ?? "" })}
        />
        <IonInput
          label="Default burst"
          labelPlacement="stacked"
          type="number"
          value={value.defaultBurst}
          onIonInput={(e) => setDefault({ defaultBurst: e.detail.value ?? "" })}
        />
      </div>
      {value.perAction.map((r, i) => (
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
      <IonButton fill="outline" size="small" onClick={addRow}>
        <IonIcon slot="start" icon={addOutline} />
        Add per-action limit
      </IonButton>
    </div>
  );
}
