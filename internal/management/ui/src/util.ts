// Small shared helpers for the management UI.

import type { Limit } from "./types";

// fmtTime renders an RFC3339 timestamp as a locale string, or a dash if absent.
export function fmtTime(ts?: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// splitList parses a comma/space/newline-separated string into trimmed,
// non-empty entries. Used for the actions/resources editors.
export function splitList(s: string): string[] {
  return s
    .split(/[\n,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

// fmtLimit renders a Limit compactly, e.g. "120/min (burst 5)".
export function fmtLimit(l?: Limit): string {
  if (!l || !l.perMinute) return "unlimited";
  return l.burst ? `${l.perMinute}/min (burst ${l.burst})` : `${l.perMinute}/min`;
}

// parseLimit turns a "perMinute[/burst]" input into a Limit, or undefined when
// blank. Returns null on a malformed value so callers can surface an error.
export function parseLimit(perMinute: string, burst: string): Limit | undefined | null {
  const pm = perMinute.trim();
  if (!pm) return undefined;
  const pmNum = Number(pm);
  if (!isFinite(pmNum) || pmNum < 0) return null;
  const out: Limit = { perMinute: pmNum };
  const b = burst.trim();
  if (b) {
    const bNum = Number(b);
    if (!Number.isInteger(bNum) || bNum < 0) return null;
    out.burst = bNum;
  }
  return out;
}
