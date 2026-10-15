import type { Context, Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { z } from "zod";
import { normalizeCode } from "../../db/repo.js";
import type { Principal, Scope } from "../../policy.js";
import { ActionError, eventPayload, overridePayload, requestPayload } from "../../service.js";
import { summarize } from "../../technitium/logs.js";
import type { OutboundEvent } from "../../webhooks.js";
import type { Deps } from "../context.js";
import type { AdminEnv } from "../admin/auth.js";

// JSON API shared by the web UI and integrations (Home Assistant). Auth is either the session
// cookie or `Authorization: Bearer <integration token>` + `X-Actor: <user>`.

type User = Extract<Principal, { kind: "user" }>;

const scopeInput = z.string().min(1); // "global" or a VLAN id

const createOverride = z.object({
  scope: scopeInput,
  kind: z.enum(["allow", "pause"]),
  domains: z.array(z.string()).optional(),
  domain: z.string().optional(),
  duration: z.string(),
});

const approveInput = z.object({
  action: z.enum(["allow", "pause"]).default("allow"),
  duration: z.string(),
  extraDomains: z.array(z.string()).default([]),
});

export function mountApi(app: Hono<AdminEnv>, deps: Deps) {
  const { policy, repo, service } = deps;

  const toScope = (s: string): Scope => (s === "global" ? { kind: "global" } : { kind: "vlan", vlanId: s });

  const user = (c: Context<AdminEnv>): User => {
    const p = c.get("principal");
    if (p?.kind !== "user") throw new ActionError(403, "Authentication required");
    return p;
  };

  const visibleVlans = (u: User) =>
    policy.vlans.filter((v) => policy.isAdmin(u) || policy.canManage(u, { kind: "vlan", vlanId: v.id }));

  const handle =
    (fn: (c: Context<AdminEnv>) => Promise<Response> | Response) =>
    async (c: Context<AdminEnv>) => {
      try {
        return await fn(c);
      } catch (err) {
        if (err instanceof ActionError) return c.json({ error: err.message }, err.status);
        if (err instanceof z.ZodError) return c.json({ error: "invalid body", issues: err.issues }, 400);
        throw err;
      }
    };

  const body = async <T>(c: Context<AdminEnv>, schema: z.ZodType<T>): Promise<T> => {
    let raw: unknown;
    try {
      raw = await c.req.json();
    } catch {
      throw new ActionError(400, "Body must be JSON");
    }
    return schema.parse(raw);
  };

  app.get(
    "/api/v1/me",
    handle((c) => {
      const u = user(c);
      return c.json({ username: u.username, name: u.name, groups: u.groups, via: u.via, admin: policy.isAdmin(u) });
    }),
  );

  /** Everything a dashboard (or an HA integration's coordinator) needs in one call. */
  app.get(
    "/api/v1/status",
    handle((c) => {
      const u = user(c);
      const active = repo.activeOverrides();
      const pauseOf = (scope: Scope) =>
        active.find(
          (o) =>
            o.kind === "pause" && (scope.kind === "global" ? o.scope === "global" : o.vlanId === scope.vlanId),
        );
      const describe = (scope: Scope) => ({
        paused: pauseOf(scope) ? overridePayload(pauseOf(scope)!) : null,
        actions: Object.fromEntries(
          (["allowTemporary", "allowPermanent", "pause"] as const).map((a) => [
            a,
            policy.can(u, scope, a) ? policy.durations(scope, a) : [],
          ]),
        ),
      });
      const vlans = visibleVlans(u);
      return c.json({
        global: describe({ kind: "global" }),
        vlans: vlans.map((v) => ({ id: v.id, name: v.name, group: v.group, ...describe({ kind: "vlan", vlanId: v.id }) })),
        pendingRequests: repo.listRequests({ status: "pending", vlanIds: vlans.map((v) => v.id) }).length,
        sync: deps.reconciler.status,
      });
    }),
  );

  app.get(
    "/api/v1/overrides",
    handle((c) => {
      const u = user(c);
      const ids = new Set(visibleVlans(u).map((v) => v.id));
      return c.json(
        repo
          .activeOverrides()
          .filter((o) => o.scope === "global" || ids.has(o.vlanId!))
          .map((o) => ({ ...overridePayload(o), canRevoke: service.canRevoke(u, o) })),
      );
    }),
  );

  app.post(
    "/api/v1/overrides",
    handle(async (c) => {
      const u = user(c);
      const input = await body(c, createOverride);
      const scope = toScope(input.scope);
      if (input.kind === "pause") {
        return c.json([overridePayload(service.pause(u, { scope, duration: input.duration }))], 201);
      }
      const domains = input.domains ?? (input.domain ? [input.domain] : []);
      return c.json(service.allow(u, { scope, domains, duration: input.duration }).map(overridePayload), 201);
    }),
  );

  app.delete(
    "/api/v1/overrides/:id",
    handle((c) => c.json(overridePayload(service.revoke(user(c), Number(c.req.param("id")))))),
  );

  app.get(
    "/api/v1/requests",
    handle((c) => {
      const u = user(c);
      const status = c.req.query("status") as "pending" | "approved" | "denied" | undefined;
      const reqs = repo.listRequests({ status: status ?? "pending", vlanIds: visibleVlans(u).map((v) => v.id) });
      return c.json(
        reqs.map((r) => {
          const e = repo.eventById(r.blockEventId);
          return {
            ...requestPayload(r),
            code: e?.code,
            clientIp: e?.clientIp,
            clientName: e?.clientName,
            approveUrl: e ? `${deps.config.policy.admin.publicUrl.replace(/\/$/, "")}/r/${e.code}` : null,
          };
        }),
      );
    }),
  );

  app.post(
    "/api/v1/requests/:id/approve",
    handle(async (c) => {
      const input = await body(c, approveInput);
      const created = service.approveRequest(user(c), Number(c.req.param("id")), input);
      return c.json(created.map(overridePayload));
    }),
  );

  app.post(
    "/api/v1/requests/:id/deny",
    handle((c) => c.json(requestPayload(service.denyRequest(user(c), Number(c.req.param("id")))))),
  );

  app.get(
    "/api/v1/codes/:code",
    handle((c) => {
      const u = user(c);
      const code = normalizeCode(c.req.param("code") ?? "");
      const e = code ? repo.eventByCode(code) : undefined;
      if (!e || !visibleVlans(u).some((v) => v.id === e.vlanId)) throw new ActionError(404, "Code not found");
      return c.json({ ...eventPayload(e), state: service.eventState(e) });
    }),
  );

  /** Recently blocked queries from Technitium's query log, grouped per device + domain. */
  app.get(
    "/api/v1/blocked",
    handle(async (c) => {
      const u = user(c);
      const minutes = Math.min(Number(c.req.query("minutes") ?? 120) || 120, 24 * 60);
      const vlanFilter = c.req.query("vlan");
      const ids = new Set(visibleVlans(u).map((v) => v.id));
      const queries = await deps.blockLog.recentBlocked({ since: new Date(Date.now() - minutes * 60_000), limit: 1000 });
      const rows = summarize(queries)
        .map((r) => ({ ...r, vlanId: policy.vlanForIp(r.clientIp)?.id ?? null }))
        .filter((r) => r.vlanId && ids.has(r.vlanId) && (!vlanFilter || r.vlanId === vlanFilter))
        .slice(0, 200);
      return c.json(rows.map((r) => ({ ...r, lastSeen: new Date(r.lastSeen).toISOString() })));
    }),
  );

  /** Server-sent events stream of the same events sent to webhooks (filtered to visible VLANs). */
  app.get("/api/v1/stream", (c) => {
    const p = c.get("principal");
    if (p?.kind !== "user") return c.json({ error: "Authentication required" }, 403);
    const ids = new Set(visibleVlans(p).map((v) => v.id));
    return streamSSE(c, async (stream) => {
      const queue: (OutboundEvent | "ping")[] = [];
      let wake: (() => void) | null = null;
      const push = (item: OutboundEvent | "ping") => {
        queue.push(item);
        wake?.();
      };
      const unsubscribe = deps.events.subscribe((e) => {
        const vlanId = e.data.vlanId as string | null | undefined;
        if (!vlanId || ids.has(vlanId)) push(e);
      });
      const keepalive = setInterval(() => push("ping"), 25_000);
      stream.onAbort(() => wake?.());
      try {
        while (!stream.aborted) {
          const next = queue.shift();
          if (next === "ping") await stream.writeSSE({ event: "ping", data: "{}" });
          else if (next) await stream.writeSSE({ event: next.type, data: JSON.stringify(next) });
          else {
            await new Promise<void>((r) => (wake = r));
            wake = null;
          }
        }
      } finally {
        clearInterval(keepalive);
        unsubscribe();
      }
    });
  });
}
