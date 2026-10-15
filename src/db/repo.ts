import { randomInt } from "node:crypto";
import type { DB } from "./db.js";

export interface BlockEvent {
  id: number;
  code: string;
  vlanId: string;
  clientIp: string;
  clientName: string | null;
  domain: string;
  url: string;
  createdAt: number;
  expiresAt: number;
}

export type RequestStatus = "pending" | "approved" | "denied";

export interface UnblockRequest {
  id: number;
  blockEventId: number;
  vlanId: string;
  domain: string;
  note: string | null;
  status: RequestStatus;
  createdAt: number;
  decidedBy: string | null;
  decidedAt: number | null;
}

export interface Override {
  id: number;
  scope: "global" | "vlan";
  vlanId: string | null;
  kind: "allow" | "pause";
  domain: string | null;
  expiresAt: number | null;
  createdBy: string;
  createdAt: number;
  revokedAt: number | null;
  revokedBy: string | null;
  blockEventId: number | null;
  requestId: number | null;
}

export interface NewOverride {
  scope: "global" | "vlan";
  vlanId: string | null;
  kind: "allow" | "pause";
  domain: string | null;
  expiresAt: number | null;
  createdBy: string;
  blockEventId?: number | null;
  requestId?: number | null;
}

export interface AuditEntry {
  id: number;
  ts: number;
  actor: string;
  action: string;
  details: Record<string, unknown>;
}

// No 0/O/1/I/L to keep codes easy to read aloud and type on a phone.
const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

export function generateCode(): string {
  let s = "";
  for (let i = 0; i < 6; i++) s += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return `${s.slice(0, 3)}-${s.slice(3)}`;
}

/** Accept "k7f2qd", "K7F 2QD", "k7f-2qd" etc. */
export function normalizeCode(input: string): string | null {
  const s = input.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (s.length !== 6) return null;
  return `${s.slice(0, 3)}-${s.slice(3)}`;
}

type Row = Record<string, unknown>;

const toEvent = (r: Row): BlockEvent => ({
  id: r.id as number,
  code: r.code as string,
  vlanId: r.vlan_id as string,
  clientIp: r.client_ip as string,
  clientName: (r.client_name as string | null) ?? null,
  domain: r.domain as string,
  url: r.url as string,
  createdAt: r.created_at as number,
  expiresAt: r.expires_at as number,
});

const toRequest = (r: Row): UnblockRequest => ({
  id: r.id as number,
  blockEventId: r.block_event_id as number,
  vlanId: r.vlan_id as string,
  domain: r.domain as string,
  note: (r.note as string | null) ?? null,
  status: r.status as RequestStatus,
  createdAt: r.created_at as number,
  decidedBy: (r.decided_by as string | null) ?? null,
  decidedAt: (r.decided_at as number | null) ?? null,
});

const toOverride = (r: Row): Override => ({
  id: r.id as number,
  scope: r.scope as Override["scope"],
  vlanId: (r.vlan_id as string | null) ?? null,
  kind: r.kind as Override["kind"],
  domain: (r.domain as string | null) ?? null,
  expiresAt: (r.expires_at as number | null) ?? null,
  createdBy: r.created_by as string,
  createdAt: r.created_at as number,
  revokedAt: (r.revoked_at as number | null) ?? null,
  revokedBy: (r.revoked_by as string | null) ?? null,
  blockEventId: (r.block_event_id as number | null) ?? null,
  requestId: (r.request_id as number | null) ?? null,
});

export class Repo {
  constructor(readonly db: DB) {}

  // ---- block events ----

  /** Reuse a recent event for the same device + domain so reloads keep the same code. */
  findRecentEvent(clientIp: string, domain: string, now = Date.now()): BlockEvent | undefined {
    const r = this.db
      .prepare(
        `SELECT * FROM block_events WHERE client_ip = ? AND domain = ? AND expires_at > ?
         ORDER BY created_at DESC LIMIT 1`,
      )
      .get(clientIp, domain, now) as Row | undefined;
    return r ? toEvent(r) : undefined;
  }

  createEvent(e: Omit<BlockEvent, "id" | "code">): BlockEvent {
    for (let attempt = 0; attempt < 5; attempt++) {
      const code = generateCode();
      try {
        const info = this.db
          .prepare(
            `INSERT INTO block_events (code, vlan_id, client_ip, client_name, domain, url, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(code, e.vlanId, e.clientIp, e.clientName, e.domain, e.url, e.createdAt, e.expiresAt);
        return { ...e, id: Number(info.lastInsertRowid), code };
      } catch (err) {
        if (!(err instanceof Error && /UNIQUE/.test(err.message))) throw err;
      }
    }
    throw new Error("Could not allocate a unique block code");
  }

  eventByCode(code: string): BlockEvent | undefined {
    const r = this.db.prepare(`SELECT * FROM block_events WHERE code = ?`).get(code) as Row | undefined;
    return r ? toEvent(r) : undefined;
  }

  eventById(id: number): BlockEvent | undefined {
    const r = this.db.prepare(`SELECT * FROM block_events WHERE id = ?`).get(id) as Row | undefined;
    return r ? toEvent(r) : undefined;
  }

  recentEvents(opts: { since: number; vlanIds?: string[]; clientIp?: string; limit?: number }): BlockEvent[] {
    const where = ["created_at >= ?"];
    const params: unknown[] = [opts.since];
    if (opts.vlanIds) {
      if (opts.vlanIds.length === 0) return [];
      where.push(`vlan_id IN (${opts.vlanIds.map(() => "?").join(",")})`);
      params.push(...opts.vlanIds);
    }
    if (opts.clientIp) {
      where.push("client_ip = ?");
      params.push(opts.clientIp);
    }
    params.push(opts.limit ?? 100);
    return (
      this.db
        .prepare(`SELECT * FROM block_events WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT ?`)
        .all(...params) as Row[]
    ).map(toEvent);
  }

  // ---- requests ----

  createRequest(event: BlockEvent, note: string | null, now = Date.now()): UnblockRequest {
    const existing = this.pendingRequestForEvent(event.id);
    if (existing) return existing;
    const info = this.db
      .prepare(
        `INSERT INTO requests (block_event_id, vlan_id, domain, note, status, created_at)
         VALUES (?, ?, ?, ?, 'pending', ?)`,
      )
      .run(event.id, event.vlanId, event.domain, note, now);
    return this.requestById(Number(info.lastInsertRowid))!;
  }

  requestById(id: number): UnblockRequest | undefined {
    const r = this.db.prepare(`SELECT * FROM requests WHERE id = ?`).get(id) as Row | undefined;
    return r ? toRequest(r) : undefined;
  }

  pendingRequestForEvent(eventId: number): UnblockRequest | undefined {
    const r = this.db
      .prepare(`SELECT * FROM requests WHERE block_event_id = ? AND status = 'pending'`)
      .get(eventId) as Row | undefined;
    return r ? toRequest(r) : undefined;
  }

  latestRequestForEvent(eventId: number): UnblockRequest | undefined {
    const r = this.db
      .prepare(`SELECT * FROM requests WHERE block_event_id = ? ORDER BY created_at DESC, id DESC LIMIT 1`)
      .get(eventId) as Row | undefined;
    return r ? toRequest(r) : undefined;
  }

  listRequests(opts: { status?: RequestStatus; vlanIds?: string[]; limit?: number }): UnblockRequest[] {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.status) {
      where.push("status = ?");
      params.push(opts.status);
    }
    if (opts.vlanIds) {
      if (opts.vlanIds.length === 0) return [];
      where.push(`vlan_id IN (${opts.vlanIds.map(() => "?").join(",")})`);
      params.push(...opts.vlanIds);
    }
    params.push(opts.limit ?? 100);
    const sql = `SELECT * FROM requests ${where.length ? "WHERE " + where.join(" AND ") : ""}
                 ORDER BY created_at DESC LIMIT ?`;
    return (this.db.prepare(sql).all(...params) as Row[]).map(toRequest);
  }

  decideRequest(id: number, status: "approved" | "denied", decidedBy: string, now = Date.now()): boolean {
    const info = this.db
      .prepare(`UPDATE requests SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'`)
      .run(status, decidedBy, now, id);
    return info.changes > 0;
  }

  // ---- overrides ----

  createOverride(o: NewOverride, now = Date.now()): Override {
    const info = this.db
      .prepare(
        `INSERT INTO overrides (scope, vlan_id, kind, domain, expires_at, created_by, created_at, block_event_id, request_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        o.scope,
        o.vlanId,
        o.kind,
        o.domain,
        o.expiresAt,
        o.createdBy,
        now,
        o.blockEventId ?? null,
        o.requestId ?? null,
      );
    return this.overrideById(Number(info.lastInsertRowid))!;
  }

  overrideById(id: number): Override | undefined {
    const r = this.db.prepare(`SELECT * FROM overrides WHERE id = ?`).get(id) as Row | undefined;
    return r ? toOverride(r) : undefined;
  }

  activeOverrides(now = Date.now()): Override[] {
    return (
      this.db
        .prepare(
          `SELECT * FROM overrides WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
           ORDER BY created_at DESC`,
        )
        .all(now) as Row[]
    ).map(toOverride);
  }

  /** Soonest future expiry among active overrides, so the reconciler can wake up exactly then. */
  nextExpiry(now = Date.now()): number | null {
    const r = this.db
      .prepare(`SELECT MIN(expires_at) AS t FROM overrides WHERE revoked_at IS NULL AND expires_at > ?`)
      .get(now) as { t: number | null };
    return r.t;
  }

  revokeOverride(id: number, revokedBy: string, now = Date.now()): boolean {
    const info = this.db
      .prepare(`UPDATE overrides SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`)
      .run(now, revokedBy, id);
    return info.changes > 0;
  }

  // ---- reconciler bookkeeping ----

  managedAllowed(): Map<string, Set<string>> {
    const out = new Map<string, Set<string>>();
    for (const r of this.db.prepare(`SELECT group_name, domain FROM managed_allowed`).all() as Row[]) {
      const g = r.group_name as string;
      if (!out.has(g)) out.set(g, new Set());
      out.get(g)!.add(r.domain as string);
    }
    return out;
  }

  managedFlags(): Map<string, string> {
    return new Map(
      (this.db.prepare(`SELECT key, value FROM managed_flags`).all() as Row[]).map((r) => [
        r.key as string,
        r.value as string,
      ]),
    );
  }

  saveManagedState(allowed: Map<string, Set<string>>, flags: Map<string, string>): void {
    this.db.transaction(() => {
      this.db.prepare(`DELETE FROM managed_allowed`).run();
      const ins = this.db.prepare(`INSERT INTO managed_allowed (group_name, domain) VALUES (?, ?)`);
      for (const [g, domains] of allowed) for (const d of domains) ins.run(g, d);
      this.db.prepare(`DELETE FROM managed_flags`).run();
      const insF = this.db.prepare(`INSERT INTO managed_flags (key, value) VALUES (?, ?)`);
      for (const [k, v] of flags) insF.run(k, v);
    })();
  }

  // ---- audit ----

  audit(actor: string, action: string, details: Record<string, unknown>, now = Date.now()): void {
    this.db
      .prepare(`INSERT INTO audit_log (ts, actor, action, details) VALUES (?, ?, ?, ?)`)
      .run(now, actor, action, JSON.stringify(details));
  }

  recentAudit(limit = 50): AuditEntry[] {
    return (this.db.prepare(`SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?`).all(limit) as Row[]).map(
      (r) => ({
        id: r.id as number,
        ts: r.ts as number,
        actor: r.actor as string,
        action: r.action as string,
        details: JSON.parse(r.details as string) as Record<string, unknown>,
      }),
    );
  }

  /** Drop expired block events (and their requests) older than `before`. */
  prune(before: number): void {
    this.db.transaction(() => {
      this.db
        .prepare(
          `UPDATE overrides SET block_event_id = NULL
           WHERE block_event_id IN (SELECT id FROM block_events WHERE expires_at < ?)`,
        )
        .run(before);
      this.db
        .prepare(
          `UPDATE overrides SET request_id = NULL WHERE request_id IN
           (SELECT r.id FROM requests r JOIN block_events e ON e.id = r.block_event_id WHERE e.expires_at < ?)`,
        )
        .run(before);
      this.db
        .prepare(`DELETE FROM requests WHERE block_event_id IN (SELECT id FROM block_events WHERE expires_at < ?)`)
        .run(before);
      this.db.prepare(`DELETE FROM block_events WHERE expires_at < ?`).run(before);
    })();
  }
}
