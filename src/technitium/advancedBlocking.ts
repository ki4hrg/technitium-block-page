// Pure rendering of our overrides into the Advanced Blocking app config.
// Config reference: https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps/AdvancedBlockingApp
//
// We only ever touch three things, and track what we changed so manual edits made in the
// Technitium UI survive:
//   - groups[].allowed       (entries we add are recorded in managed.allowed)
//   - groups[].enableBlocking (original value recorded in managed.flags while paused)
//   - top-level enableBlocking (same, for a global pause)

export interface AdvancedBlockingGroup {
  name: string;
  enableBlocking?: boolean;
  allowed?: string[];
  blockingAddresses?: string[];
  blockAsNxDomain?: boolean;
  [key: string]: unknown;
}

export interface AdvancedBlockingConfig {
  enableBlocking?: boolean;
  blockingAnswerTtl?: number;
  networkGroupMap?: Record<string, string>;
  localEndPointGroupMap?: Record<string, string>;
  groups?: AdvancedBlockingGroup[];
  [key: string]: unknown;
}

export interface DesiredState {
  /** Domains to allow per group. */
  allowed: Map<string, Set<string>>;
  /** Domains to allow in every group (global overrides). */
  allowedEverywhere: Set<string>;
  pausedGroups: Set<string>;
  globalPause: boolean;
}

export interface ManagedState {
  allowed: Map<string, Set<string>>;
  flags: Map<string, string>;
}

export interface RenderResult {
  config: AdvancedBlockingConfig;
  managed: ManagedState;
  changed: boolean;
  warnings: string[];
}

export const TOP_FLAG = "top:enableBlocking";
export const groupFlag = (group: string) => `group:${group}:enableBlocking`;

export function normalizeDomain(d: string): string {
  return d.trim().toLowerCase().replace(/\.$/, "");
}

export function emptyDesired(): DesiredState {
  return { allowed: new Map(), allowedEverywhere: new Set(), pausedGroups: new Set(), globalPause: false };
}

export function render(current: AdvancedBlockingConfig, desired: DesiredState, managed: ManagedState): RenderResult {
  const config = structuredClone(current);
  const warnings: string[] = [];
  const nextAllowed = new Map<string, Set<string>>();
  const nextFlags = new Map<string, string>();
  const groups = config.groups ?? [];
  const groupNames = new Set(groups.map((g) => g.name));

  for (const name of [...desired.allowed.keys(), ...desired.pausedGroups]) {
    if (!groupNames.has(name)) warnings.push(`Advanced Blocking group "${name}" does not exist; override not applied`);
  }

  for (const group of groups) {
    // Allowed list: strip what we previously added, then add what should be active now.
    const previouslyManaged = managed.allowed.get(group.name) ?? new Set<string>();
    const base = (group.allowed ?? []).filter((d) => !previouslyManaged.has(normalizeDomain(d)));
    const baseSet = new Set(base.map(normalizeDomain));
    const want = new Set([...(desired.allowed.get(group.name) ?? []), ...desired.allowedEverywhere]);
    const ours = [...want].map(normalizeDomain).filter((d) => !baseSet.has(d)).sort();
    if (group.allowed !== undefined || ours.length > 0) group.allowed = [...base, ...ours];
    if (ours.length > 0) nextAllowed.set(group.name, new Set(ours));

    // Per-group pause.
    const key = groupFlag(group.name);
    const original = managed.flags.get(key);
    if (desired.pausedGroups.has(group.name)) {
      nextFlags.set(key, original ?? String(group.enableBlocking ?? true));
      group.enableBlocking = false;
    } else if (original !== undefined) {
      group.enableBlocking = original === "true";
    }
  }

  // Global pause. Flags for groups that no longer exist are dropped.
  const topOriginal = managed.flags.get(TOP_FLAG);
  if (desired.globalPause) {
    nextFlags.set(TOP_FLAG, topOriginal ?? String(config.enableBlocking ?? true));
    config.enableBlocking = false;
  } else if (topOriginal !== undefined) {
    config.enableBlocking = topOriginal === "true";
  }

  return {
    config,
    managed: { allowed: nextAllowed, flags: nextFlags },
    changed: JSON.stringify(config) !== JSON.stringify(current),
    warnings,
  };
}
