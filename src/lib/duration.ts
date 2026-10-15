// Durations offered in policy: "15m", "1h", "2d", "today" (until local midnight), "permanent".

export type DurationSpec = string;

const UNIT_MS: Record<string, number> = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

export function isValidDuration(spec: string): boolean {
  return spec === "today" || spec === "permanent" || /^\d+[smhd]$/.test(spec);
}

/** Absolute expiry (ms epoch) for a duration starting at `now`; null means permanent. */
export function resolveExpiry(spec: DurationSpec, now: number = Date.now()): number | null {
  if (spec === "permanent") return null;
  if (spec === "today") {
    const d = new Date(now);
    return new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1).getTime();
  }
  const m = /^(\d+)([smhd])$/.exec(spec);
  if (!m) throw new Error(`Invalid duration: ${spec}`);
  return now + Number(m[1]) * UNIT_MS[m[2]!]!;
}

export function durationLabel(spec: DurationSpec): string {
  if (spec === "today") return "Rest of today";
  if (spec === "permanent") return "Permanently";
  const m = /^(\d+)([smhd])$/.exec(spec);
  if (!m) return spec;
  const n = Number(m[1]);
  const unit = { s: "second", m: "minute", h: "hour", d: "day" }[m[2]!]!;
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

export function formatRemaining(expiresAt: number | null, now: number = Date.now()): string {
  if (expiresAt === null) return "permanent";
  const ms = expiresAt - now;
  if (ms <= 0) return "expired";
  const mins = Math.ceil(ms / 60_000);
  if (mins < 60) return `${mins}m left`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ${mins % 60}m left`;
  return `${Math.floor(hours / 24)}d left`;
}
