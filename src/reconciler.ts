import type { Override, Repo } from "./db/repo.js";
import type { Logger } from "./lib/log.js";
import type { Policy } from "./policy.js";
import {
  emptyDesired,
  normalizeDomain,
  render,
  type AdvancedBlockingConfig,
  type DesiredState,
} from "./technitium/advancedBlocking.js";
import type { TechnitiumClient } from "./technitium/client.js";

const BUILTIN_FLAG = "builtin:paused";
const TICK_MS = 30_000;
const DEBOUNCE_MS = 300;

export function desiredFromOverrides(overrides: Override[], policy: Policy): DesiredState {
  const desired = emptyDesired();
  for (const o of overrides) {
    const group = o.scope === "vlan" ? policy.vlan(o.vlanId!)?.group : undefined;
    if (o.scope === "vlan" && !group) continue; // VLAN removed from policy
    if (o.kind === "allow") {
      const domain = normalizeDomain(o.domain!);
      if (o.scope === "global") desired.allowedEverywhere.add(domain);
      else {
        if (!desired.allowed.has(group!)) desired.allowed.set(group!, new Set());
        desired.allowed.get(group!)!.add(domain);
      }
    } else if (o.scope === "global") desired.globalPause = true;
    else desired.pausedGroups.add(group!);
  }
  return desired;
}

export interface ReconcilerStatus {
  lastRunAt: number | null;
  lastSuccessAt: number | null;
  lastWriteAt: number | null;
  lastError: string | null;
  warnings: string[];
  /** blockingAnswerTtl from the live Advanced Blocking config (seconds). */
  blockingAnswerTtl: number;
}

export class Reconciler {
  readonly status: ReconcilerStatus = {
    lastRunAt: null,
    lastSuccessAt: null,
    lastWriteAt: null,
    lastError: null,
    warnings: [],
    blockingAnswerTtl: 30,
  };
  private chain: Promise<void> = Promise.resolve();
  private debounce: NodeJS.Timeout | null = null;
  private tick: NodeJS.Timeout | null = null;
  private expiryTimer: NodeJS.Timeout | null = null;
  /** Fires after each successful pass that changed Technitium. */
  onApplied: (() => void) | null = null;

  constructor(
    private readonly deps: {
      repo: Repo;
      client: TechnitiumClient;
      policy: Policy;
      log: Logger;
      appName: string;
      pauseBuiltIn: boolean;
    },
  ) {}

  start(): void {
    this.trigger();
    this.tick = setInterval(() => this.trigger(), TICK_MS);
  }

  stop(): void {
    for (const t of [this.debounce, this.expiryTimer]) if (t) clearTimeout(t);
    if (this.tick) clearInterval(this.tick);
  }

  /** Request a reconcile soon; bursts of changes are coalesced into one write. */
  trigger(): void {
    if (this.debounce) clearTimeout(this.debounce);
    this.debounce = setTimeout(() => {
      this.debounce = null;
      void this.run();
    }, DEBOUNCE_MS);
  }

  /** Run a pass now (serialized with any in-flight pass). */
  run(): Promise<void> {
    this.chain = this.chain.then(() => this.runOnce()).catch(() => undefined);
    return this.chain;
  }

  private async runOnce(): Promise<void> {
    const { repo, client, policy, log, appName } = this.deps;
    const now = Date.now();
    this.status.lastRunAt = now;
    try {
      const overrides = repo.activeOverrides(now);
      const desired = desiredFromOverrides(overrides, policy);

      const raw = await client.getAppConfig(appName);
      if (!raw) throw new Error(`Advanced Blocking app "${appName}" has no config (is it installed?)`);
      const current = JSON.parse(raw) as AdvancedBlockingConfig;
      this.status.blockingAnswerTtl = current.blockingAnswerTtl ?? 30;

      const managedFlags = repo.managedFlags();
      const result = render(current, desired, { allowed: repo.managedAllowed(), flags: managedFlags });
      for (const w of result.warnings) log.warn(w);
      this.status.warnings = result.warnings;

      if (result.changed) {
        await client.setAppConfig(appName, JSON.stringify(result.config, null, 2));
        this.status.lastWriteAt = Date.now();
        log.info("advanced blocking config updated", {
          paused: [...desired.pausedGroups],
          globalPause: desired.globalPause,
          allowedGroups: [...result.managed.allowed.keys()],
        });
      }

      // Built-in blocking ignores the app config, so a global pause pauses it separately.
      let builtinPaused = managedFlags.get(BUILTIN_FLAG) === "true";
      if (this.deps.pauseBuiltIn && (desired.globalPause || builtinPaused)) {
        builtinPaused = await this.syncBuiltIn(desired.globalPause, overrides, builtinPaused, now);
      }
      if (builtinPaused) result.managed.flags.set(BUILTIN_FLAG, "true");

      repo.saveManagedState(result.managed.allowed, result.managed.flags);
      this.status.lastSuccessAt = Date.now();
      this.status.lastError = null;
      if (result.changed) this.onApplied?.();
    } catch (err) {
      this.status.lastError = err instanceof Error ? err.message : String(err);
      log.error("reconcile failed", { error: this.status.lastError });
    } finally {
      this.scheduleNextExpiry();
    }
  }

  private async syncBuiltIn(pause: boolean, overrides: Override[], wasPaused: boolean, now: number) {
    const { client, log } = this.deps;
    const settings = await client.getSettings();
    if (pause) {
      if (settings.enableBlocking) {
        const expiries = overrides.filter((o) => o.kind === "pause" && o.scope === "global").map((o) => o.expiresAt);
        if (expiries.includes(null)) await client.setBuiltInBlocking(false);
        else {
          const until = Math.max(...(expiries as number[]));
          await client.temporaryDisableBlocking(Math.max(1, Math.ceil((until - now) / 60_000)));
        }
        log.info("built-in blocking paused");
      }
      return true;
    }
    if (wasPaused && !settings.enableBlocking) {
      await client.setBuiltInBlocking(true);
      log.info("built-in blocking resumed");
    }
    return false;
  }

  private scheduleNextExpiry(): void {
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    const next = this.deps.repo.nextExpiry();
    if (next === null) return;
    const delay = next - Date.now() + 250;
    if (delay > TICK_MS) return; // the regular tick will catch it
    this.expiryTimer = setTimeout(() => this.trigger(), Math.max(0, delay));
  }
}
