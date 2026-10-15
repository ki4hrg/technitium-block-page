import type { BlockEvent, Override, Repo, UnblockRequest } from "./db/repo.js";
import { resolveExpiry } from "./lib/duration.js";
import { normalizeIp } from "./lib/cidr.js";
import { normalizeDomain } from "./technitium/advancedBlocking.js";
import { principalLabel, type ActionName, type Policy, type Principal, type Scope } from "./policy.js";
import type { Reconciler } from "./reconciler.js";
import type { Events } from "./webhooks.js";

export class ActionError extends Error {
  constructor(
    readonly status: 400 | 403 | 404 | 409,
    message: string,
  ) {
    super(message);
  }
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function validDomain(d: string): string {
  const n = normalizeDomain(d);
  if (!DOMAIN_RE.test(n)) throw new ActionError(400, `Invalid domain: ${d}`);
  return n;
}

/** Advanced Blocking allow entries cover the domain and all of its subdomains. */
export function domainCovers(allowEntry: string, domain: string): boolean {
  return domain === allowEntry || domain.endsWith(`.${allowEntry}`);
}

export type EventState =
  | { state: "blocked" }
  | { state: "requested"; requestId: number }
  | { state: "denied"; by: string | null }
  | { state: "allowed"; overrideId: number; readyAt: number; until: number | null };

export function scopeOf(o: Pick<Override, "scope" | "vlanId">): Scope {
  return o.scope === "global" ? { kind: "global" } : { kind: "vlan", vlanId: o.vlanId! };
}

/** All state-changing operations, shared by the block page, admin UI and JSON API. */
export class Service {
  constructor(
    readonly repo: Repo,
    readonly policy: Policy,
    private readonly reconciler: Pick<Reconciler, "trigger" | "status">,
    private readonly events: Events,
    private readonly opts: { blockEventTtlMinutes: number },
  ) {}

  // ---- block events ----

  recordBlock(input: { clientIp: string; clientName: string | null; host: string; url: string }): BlockEvent | null {
    const clientIp = normalizeIp(input.clientIp);
    const vlan = this.policy.vlanForIp(clientIp);
    if (!vlan) return null;
    const domain = normalizeDomain(input.host.replace(/:\d+$/, ""));
    const existing = this.repo.findRecentEvent(clientIp, domain);
    if (existing) return existing;
    const now = Date.now();
    const event = this.repo.createEvent({
      vlanId: vlan.id,
      clientIp,
      clientName: input.clientName,
      domain,
      url: input.url,
      createdAt: now,
      expiresAt: now + this.opts.blockEventTtlMinutes * 60_000,
    });
    this.events.emit("block.created", eventPayload(event));
    return event;
  }

  /** Active override that currently unblocks this domain for this VLAN, if any. */
  coveringOverride(vlanId: string, domain: string, now = Date.now()): Override | undefined {
    return this.repo
      .activeOverrides(now)
      .find(
        (o) =>
          (o.scope === "global" || o.vlanId === vlanId) &&
          (o.kind === "pause" || domainCovers(o.domain!, domain)),
      );
  }

  eventState(event: BlockEvent, now = Date.now()): EventState {
    const o = this.coveringOverride(event.vlanId, event.domain, now);
    if (o) {
      // Clients may hold the blocked answer for up to blockingAnswerTtl after the change lands.
      const readyAt = Math.max(o.createdAt, this.reconciler.status.lastWriteAt ?? 0) +
        this.reconciler.status.blockingAnswerTtl * 1000 + 2000;
      return { state: "allowed", overrideId: o.id, readyAt, until: o.expiresAt };
    }
    const req = this.repo.latestRequestForEvent(event.id);
    if (req?.status === "pending") return { state: "requested", requestId: req.id };
    if (req?.status === "denied") return { state: "denied", by: req.decidedBy };
    return { state: "blocked" };
  }

  // ---- overrides ----

  allow(
    p: Principal,
    input: { scope: Scope; domains: string[]; duration: string; blockEventId?: number; requestId?: number },
  ): Override[] {
    const action: ActionName = input.duration === "permanent" ? "allowPermanent" : "allowTemporary";
    this.authorize(p, input.scope, action, input.duration);
    const domains = [...new Set(input.domains.map(validDomain))];
    if (domains.length === 0) throw new ActionError(400, "No domains given");
    const expiresAt = resolveExpiry(input.duration);
    const actor = principalLabel(p);
    const created = this.repo.db.transaction(() =>
      domains.map((domain) =>
        this.repo.createOverride({
          scope: input.scope.kind,
          vlanId: input.scope.kind === "vlan" ? input.scope.vlanId : null,
          kind: "allow",
          domain,
          expiresAt,
          createdBy: actor,
          blockEventId: input.blockEventId ?? null,
          requestId: input.requestId ?? null,
        }),
      ),
    )();
    for (const o of created) this.afterCreate(actor, o);
    this.reconciler.trigger();
    return created;
  }

  pause(p: Principal, input: { scope: Scope; duration: string; blockEventId?: number; requestId?: number }): Override {
    this.authorize(p, input.scope, "pause", input.duration);
    const actor = principalLabel(p);
    const o = this.repo.createOverride({
      scope: input.scope.kind,
      vlanId: input.scope.kind === "vlan" ? input.scope.vlanId : null,
      kind: "pause",
      domain: null,
      expiresAt: resolveExpiry(input.duration),
      createdBy: actor,
      blockEventId: input.blockEventId ?? null,
      requestId: input.requestId ?? null,
    });
    this.afterCreate(actor, o);
    this.reconciler.trigger();
    return o;
  }

  canRevoke(p: Principal, o: Override): boolean {
    if (this.policy.isAdmin(p)) return true;
    if (p.kind === "user" && o.createdBy === principalLabel(p)) return true;
    const action: ActionName = o.kind === "pause" ? "pause" : o.expiresAt === null ? "allowPermanent" : "allowTemporary";
    return p.kind === "user" && this.policy.can(p, scopeOf(o), action);
  }

  revoke(p: Principal, id: number): Override {
    const o = this.repo.overrideById(id);
    if (!o || o.revokedAt !== null) throw new ActionError(404, "Override not found");
    if (!this.canRevoke(p, o)) throw new ActionError(403, "Not allowed to revoke this override");
    const actor = principalLabel(p);
    this.repo.revokeOverride(id, actor);
    this.repo.audit(actor, "override.revoked", { id, kind: o.kind, scope: o.scope, vlanId: o.vlanId, domain: o.domain });
    this.events.emit("override.revoked", { ...overridePayload(o), revokedBy: actor });
    this.reconciler.trigger();
    return this.repo.overrideById(id)!;
  }

  // ---- unblock requests ----

  requestUnblock(p: Principal, event: BlockEvent, note: string | null): UnblockRequest {
    if (!this.policy.canRequest(p, event.vlanId)) throw new ActionError(403, "Requests are not enabled here");
    if (p.kind === "network" && p.ip !== event.clientIp) throw new ActionError(403, "Not your block");
    const existing = this.repo.pendingRequestForEvent(event.id);
    if (existing) return existing;
    const req = this.repo.createRequest(event, note?.trim().slice(0, 500) || null);
    this.repo.audit(principalLabel(p), "request.created", { id: req.id, domain: event.domain, vlanId: event.vlanId });
    this.events.emit("request.created", {
      ...requestPayload(req),
      clientIp: event.clientIp,
      clientName: event.clientName,
      code: event.code,
    });
    return req;
  }

  /** Approve a request by allowing its domain (plus optional siblings) or pausing its VLAN. */
  approveRequest(
    p: Principal,
    requestId: number,
    input: { action: "allow" | "pause"; duration: string; extraDomains?: string[] },
  ): Override[] {
    const req = this.repo.requestById(requestId);
    if (!req) throw new ActionError(404, "Request not found");
    if (req.status !== "pending") throw new ActionError(409, `Request already ${req.status}`);
    const scope: Scope = { kind: "vlan", vlanId: req.vlanId };
    const created =
      input.action === "pause"
        ? [this.pause(p, { scope, duration: input.duration, blockEventId: req.blockEventId, requestId })]
        : this.allow(p, {
            scope,
            domains: [req.domain, ...(input.extraDomains ?? [])],
            duration: input.duration,
            blockEventId: req.blockEventId,
            requestId,
          });
    const actor = principalLabel(p);
    this.repo.decideRequest(requestId, "approved", actor);
    this.events.emit("request.approved", { ...requestPayload(req), decidedBy: actor, overrides: created.map((o) => o.id) });
    return created;
  }

  denyRequest(p: Principal, requestId: number): UnblockRequest {
    const req = this.repo.requestById(requestId);
    if (!req) throw new ActionError(404, "Request not found");
    if (req.status !== "pending") throw new ActionError(409, `Request already ${req.status}`);
    if (p.kind !== "user" || !this.policy.canManage(p, { kind: "vlan", vlanId: req.vlanId })) {
      throw new ActionError(403, "Not allowed to decide requests for this network");
    }
    const actor = principalLabel(p);
    this.repo.decideRequest(requestId, "denied", actor);
    this.repo.audit(actor, "request.denied", { id: requestId, domain: req.domain, vlanId: req.vlanId });
    this.events.emit("request.denied", { ...requestPayload(req), decidedBy: actor });
    return this.repo.requestById(requestId)!;
  }

  // ---- helpers ----

  private authorize(p: Principal, scope: Scope, action: ActionName, duration: string): void {
    if (scope.kind === "vlan" && !this.policy.vlan(scope.vlanId)) throw new ActionError(404, "Unknown network");
    if (!this.policy.can(p, scope, action)) throw new ActionError(403, "Not allowed");
    if (!this.policy.durations(scope, action).includes(duration)) {
      throw new ActionError(400, `Duration ${duration} not offered for this action`);
    }
  }

  private afterCreate(actor: string, o: Override): void {
    this.repo.audit(actor, "override.created", overridePayload(o));
    this.events.emit("override.created", overridePayload(o));
  }
}

export function overridePayload(o: Override) {
  return {
    id: o.id,
    scope: o.scope,
    vlanId: o.vlanId,
    kind: o.kind,
    domain: o.domain,
    expiresAt: o.expiresAt === null ? null : new Date(o.expiresAt).toISOString(),
    createdBy: o.createdBy,
    createdAt: new Date(o.createdAt).toISOString(),
    revokedAt: o.revokedAt === null ? null : new Date(o.revokedAt).toISOString(),
    revokedBy: o.revokedBy,
  };
}

export function requestPayload(r: UnblockRequest) {
  return {
    id: r.id,
    vlanId: r.vlanId,
    domain: r.domain,
    note: r.note,
    status: r.status,
    createdAt: new Date(r.createdAt).toISOString(),
    decidedBy: r.decidedBy,
  };
}

export function eventPayload(e: BlockEvent) {
  return {
    id: e.id,
    code: e.code,
    vlanId: e.vlanId,
    clientIp: e.clientIp,
    clientName: e.clientName,
    domain: e.domain,
    createdAt: new Date(e.createdAt).toISOString(),
  };
}
