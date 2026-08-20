import { IonButton, IonIcon, IonInput, IonLabel, IonSelect, IonSelectOption } from "@ionic/react";
import { addOutline, trashOutline } from "ionicons/icons";
import type { Effect, Statement } from "../types";
import { splitList } from "../util";

// A statement as edited in the form: actions/resources are free-text (comma or
// newline separated) and converted to arrays on submit via toStatements.
export interface DraftStatement {
  effect: Effect;
  actions: string;
  resources: string;
  note: string;
}

export function emptyDraft(effect: Effect = "ALLOW"): DraftStatement {
  return { effect, actions: "", resources: "", note: "" };
}

// fromStatements converts wire statements into editable drafts.
export function fromStatements(statements?: Statement[]): DraftStatement[] {
  return (statements ?? []).map((s) => ({
    effect: s.effect,
    actions: (s.actions ?? []).join(", "),
    resources: (s.resources ?? []).join(", "),
    note: s.note ?? "",
  }));
}

// toStatements converts drafts back to wire statements, dropping fully-empty
// rows. Returns null if any non-empty row is missing actions or resources.
export function toStatements(drafts: DraftStatement[]): Statement[] | null {
  const out: Statement[] = [];
  for (const d of drafts) {
    const actions = splitList(d.actions);
    const resources = splitList(d.resources);
    if (actions.length === 0 && resources.length === 0 && !d.note) continue;
    if (actions.length === 0 || resources.length === 0) return null;
    out.push({ effect: d.effect, actions, resources, note: d.note || undefined });
  }
  return out;
}

interface Props {
  drafts: DraftStatement[];
  onChange: (drafts: DraftStatement[]) => void;
  // denyOnly restricts the effect choice to deny (the global policy ceiling).
  denyOnly?: boolean;
}

// StatementsEditor renders an editable list of allow/deny statements.
export default function StatementsEditor({ drafts, onChange, denyOnly }: Props) {
  const update = (i: number, patch: Partial<DraftStatement>) =>
    onChange(drafts.map((d, j) => (j === i ? { ...d, ...patch } : d)));
  const remove = (i: number) => onChange(drafts.filter((_, j) => j !== i));
  const add = () => onChange([...drafts, emptyDraft(denyOnly ? "DENY" : "ALLOW")]);

  return (
    <div>
      {drafts.map((d, i) => (
        <div className="editor-row" key={i}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {denyOnly ? (
              <IonLabel className="mono">deny</IonLabel>
            ) : (
              <IonSelect
                label="Effect"
                value={d.effect}
                interface="popover"
                onIonChange={(e) => update(i, { effect: e.detail.value as Effect })}
              >
                <IonSelectOption value="ALLOW">allow</IonSelectOption>
                <IonSelectOption value="DENY">deny</IonSelectOption>
              </IonSelect>
            )}
            <IonButton fill="clear" color="danger" onClick={() => remove(i)}>
              <IonIcon slot="icon-only" icon={trashOutline} />
            </IonButton>
          </div>
          <IonInput
            label="Actions"
            labelPlacement="stacked"
            placeholder="photos:getAlbum, photos:list*"
            value={d.actions}
            onIonInput={(e) => update(i, { actions: e.detail.value ?? "" })}
          />
          <IonInput
            label="Resources"
            labelPlacement="stacked"
            placeholder="photos:album:a1b2, photos:*"
            value={d.resources}
            onIonInput={(e) => update(i, { resources: e.detail.value ?? "" })}
          />
          <IonInput
            label="Note (optional)"
            labelPlacement="stacked"
            value={d.note}
            onIonInput={(e) => update(i, { note: e.detail.value ?? "" })}
          />
        </div>
      ))}
      <IonButton fill="outline" size="small" onClick={add}>
        <IonIcon slot="start" icon={addOutline} />
        Add statement
      </IonButton>
    </div>
  );
}
