import type { PolicyConfig } from "./config.js";
import type { Logger } from "./lib/log.js";

export type EventType =
  | "block.created"
  | "request.created"
  | "request.approved"
  | "request.denied"
  | "override.created"
  | "override.revoked";

export interface OutboundEvent {
  type: EventType;
  ts: string;
  data: Record<string, unknown>;
}

type Listener = (e: OutboundEvent) => void;

/** Fans events out to configured webhooks (e.g. a Home Assistant webhook trigger) and in-process listeners. */
export class Events {
  private listeners = new Set<Listener>();

  constructor(
    private readonly hooks: PolicyConfig["webhooks"],
    private readonly secrets: Map<string, string>,
    private readonly log: Logger,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(type: EventType, data: Record<string, unknown>): void {
    const event: OutboundEvent = { type, ts: new Date().toISOString(), data };
    for (const fn of this.listeners) {
      try {
        fn(event);
      } catch (err) {
        this.log.error("event listener failed", { error: String(err) });
      }
    }
    for (const hook of this.hooks) {
      if (hook.events.length && !hook.events.includes(type)) continue;
      void this.deliver(hook.url, event);
    }
  }

  private async deliver(url: string, event: OutboundEvent): Promise<void> {
    const secret = this.secrets.get(url);
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await this.fetchImpl(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(secret ? { "X-Webhook-Secret": secret } : {}) },
          body: JSON.stringify(event),
          signal: AbortSignal.timeout(10_000),
        });
        if (res.ok) return;
        throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        if (attempt === 3) this.log.warn("webhook delivery failed", { url, type: event.type, error: String(err) });
        else await new Promise((r) => setTimeout(r, attempt * 2_000));
      }
    }
  }
}
