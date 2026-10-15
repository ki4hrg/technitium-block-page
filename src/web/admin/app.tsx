import { Hono, type Context } from "hono";
import type { Vlan } from "../../config.js";
import { normalizeCode, type BlockEvent, type Override } from "../../db/repo.js";
import { durationLabel, formatRemaining } from "../../lib/duration.js";
import { principalLabel, type Principal, type Scope } from "../../policy.js";
import { ActionError, domainCovers } from "../../service.js";
import { siblingDomains, summarize, type BlockedQuery } from "../../technitium/logs.js";
import type { Deps } from "../context.js";
import { fmtAgo, Layout } from "../layout.js";
import { mountApi } from "../api/v1.js";
import {
  csrfGuard,
  currentUser,
  mountAuthRoutes,
  principalMiddleware,
  requireUserPage,
  type AdminEnv,
} from "./auth.js";

type User = Extract<Principal, { kind: "user" }>;

export function createAdminApp(deps: Deps) {
  const { policy, repo, service, config } = deps;
  const publicUrl = config.policy.admin.publicUrl.replace(/\/$/, "");
  const app = new Hono<AdminEnv>();

  app.get("/healthz", (c) => {
    const ok = !deps.reconciler.status.lastError;
    return c.json({ ok, reconciler: deps.reconciler.status }, ok ? 200 : 503);
  });

  app.use("*", principalMiddleware(deps));
  app.use("*", csrfGuard(publicUrl));
  mountAuthRoutes(app, deps);
  mountApi(app, deps);

  const pages = new Hono<AdminEnv>();
  pages.use("*", requireUserPage());

  const manageable = (u: User) => policy.vlans.filter((v) => policy.canManage(u, { kind: "vlan", vlanId: v.id }));

  async function recentLogged(since: number): Promise<{ queries: BlockedQuery[]; error: string | null }> {
    try {
      return { queries: await deps.blockLog.recentBlocked({ since: new Date(since), limit: 1000 }), error: null };
    } catch (err) {
      deps.log.warn("could not read query logs", { error: String(err) });
      return { queries: [], error: "Couldn't read Technitium's query logs." };
    }
  }

  const fail = (c: Context, err: unknown) => {
    if (err instanceof ActionError) return c.html(<Message title="Can't do that" body={err.message} />, err.status);
    throw err;
  };

  // ---------- dashboard ----------

  pages.get("/", async (c) => {
    const u = currentUser(c)!;
    const vlans = manageable(u);
    const vlanIds = vlans.map((v) => v.id);
    const now = Date.now();
    const overrides = repo
      .activeOverrides(now)
      .filter((o) => o.scope === "global" || vlanIds.includes(o.vlanId!) || policy.isAdmin(u));
    const pending = repo.listRequests({ status: "pending", vlanIds });
    const { queries, error } = vlans.length ? await recentLogged(now - 2 * 3_600_000) : { queries: [], error: null };
    const recent = summarize(queries)
      .map((r) => ({ ...r, vlan: policy.vlanForIp(r.clientIp) }))
      .filter((r): r is typeof r & { vlan: Vlan } => !!r.vlan && vlanIds.includes(r.vlan.id))
      .slice(0, 60);
    const names = new Map(
      await Promise.all(
        [...new Set(recent.map((r) => r.clientIp))].map(async (ip) => [ip, await deps.blockLog.clientName(ip)] as const),
      ),
    );
    const globalScope: Scope = { kind: "global" };
    const globalPause = overrides.find((o) => o.kind === "pause" && o.scope === "global");
    const status = deps.reconciler.status;

    return c.html(
      <Layout title="Blocks" nav={<Nav user={u} />}>
        {status.lastError ? (
          <p class="notice error small">Technitium sync is failing: {status.lastError}</p>
        ) : null}
        {status.warnings.map((w) => (
          <p class="notice small">{w}</p>
        ))}

        <section class="card">
          <h2>Enter a block code</h2>
          <form method="get" action="/lookup" class="row">
            <input type="text" name="code" placeholder="K7F-2QD" autocomplete="off" autocapitalize="characters"
              style="text-transform:uppercase;width:10em" required />
            <button class="primary" type="submit">Look up</button>
          </form>
        </section>

        {pending.length ? (
          <section class="card">
            <h2>Waiting for approval</h2>
            <ul class="list">
              {pending.map((r) => {
                const e = repo.eventById(r.blockEventId);
                return (
                  <li class="row between">
                    <div>
                      <div class="domain">{r.domain}</div>
                      <div class="muted small">
                        {policy.vlan(r.vlanId)?.name} · {e?.clientName ?? e?.clientIp} · {fmtAgo(r.createdAt)}
                        {r.note ? <> · “{r.note}”</> : null}
                      </div>
                    </div>
                    {e ? <a class="btn primary" href={`/r/${e.code}`}>Review</a> : null}
                  </li>
                );
              })}
            </ul>
          </section>
        ) : null}

        {vlans.length || policy.can(u, globalScope, "pause") ? (
          <section class="card">
            <h2>Blocking</h2>
            <ul class="list">
              {policy.can(u, globalScope, "pause") || globalPause ? (
                <PauseRow
                  label="Everywhere"
                  scope={globalScope}
                  active={globalPause}
                  user={u}
                />
              ) : null}
              {vlans.map((v) => (
                <PauseRow
                  label={v.name}
                  scope={{ kind: "vlan", vlanId: v.id }}
                  active={overrides.find((o) => o.kind === "pause" && o.scope === "vlan" && o.vlanId === v.id)}
                  user={u}
                />
              ))}
            </ul>
          </section>
        ) : null}

        <section class="card">
          <h2>Active exceptions</h2>
          {overrides.filter((o) => o.kind === "allow").length ? (
            <ul class="list">
              {overrides
                .filter((o) => o.kind === "allow")
                .map((o) => (
                  <li class="row between">
                    <div>
                      <div class="domain">{o.domain}</div>
                      <div class="muted small">
                        {o.scope === "global" ? "All networks" : policy.vlan(o.vlanId!)?.name} ·{" "}
                        {formatRemaining(o.expiresAt)} · by {o.createdBy}
                      </div>
                    </div>
                    {service.canRevoke(u, o) ? <RevokeButton id={o.id} label="Remove" /> : null}
                  </li>
                ))}
            </ul>
          ) : (
            <p class="muted">None.</p>
          )}
        </section>

        {vlans.length ? (
          <section class="card">
            <h2>Recently blocked</h2>
            <p class="muted small">Last two hours, from Technitium's query log.</p>
            {error ? <p class="notice small">{error}</p> : null}
            {recent.length ? (
              <ul class="list">
                {recent.map((r) => {
                  const scope: Scope = { kind: "vlan", vlanId: r.vlan.id };
                  const durations = [
                    ...(policy.can(u, scope, "allowTemporary") ? policy.durations(scope, "allowTemporary") : []),
                    ...(policy.can(u, scope, "allowPermanent") ? ["permanent"] : []),
                  ];
                  const allowed = overrides.some(
                    (o) =>
                      o.kind === "allow" &&
                      (o.scope === "global" || o.vlanId === r.vlan.id) &&
                      domainCovers(o.domain!, r.domain),
                  );
                  return (
                    <li class="row between">
                      <div>
                        <div class="domain">{r.domain}</div>
                        <div class="muted small">
                          {r.vlan.name} · {names.get(r.clientIp) ?? r.clientIp} · {r.count}× · {fmtAgo(r.lastSeen)}
                        </div>
                      </div>
                      {allowed ? (
                        <span class="chip ok">allowed</span>
                      ) : durations.length ? (
                        <form method="post" action="/allow" class="row">
                          <input type="hidden" name="vlanId" value={r.vlan.id} />
                          <input type="hidden" name="domain" value={r.domain} />
                          <select name="duration" aria-label="Duration">
                            {durations.map((d) => (
                              <option value={d}>{durationLabel(d)}</option>
                            ))}
                          </select>
                          <button type="submit">Allow</button>
                        </form>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p class="muted">Nothing blocked recently.</p>
            )}
          </section>
        ) : null}

        {policy.isAdmin(u) ? <AuditCard entries={repo.recentAudit(25)} /> : null}
      </Layout>,
    );
  });

  pages.get("/lookup", (c) => {
    const code = normalizeCode(c.req.query("code") ?? "");
    if (!code) return c.html(<Message title="Invalid code" body="Codes look like K7F-2QD." back="/" />, 400);
    return c.redirect(`/r/${code}`);
  });

  // ---------- approve a specific block ----------

  pages.get("/r/:code", async (c) => {
    const u = currentUser(c)!;
    const code = normalizeCode(c.req.param("code"));
    const e = code ? repo.eventByCode(code) : undefined;
    if (!e || e.expiresAt < Date.now())
      return c.html(<Message title="Code not found" body="That code doesn't exist or has expired." back="/" />, 404);
    const vlan = policy.vlan(e.vlanId);
    const scope: Scope = { kind: "vlan", vlanId: e.vlanId };
    if (!vlan || !policy.canManage(u, scope)) {
      return c.html(
        <Message title="Not allowed" body={`You can't manage blocks on ${vlan?.name ?? "this network"}.`} back="/" />,
        403,
      );
    }
    const ret = validReturn(c.req.query("return"), e);
    const state = service.eventState(e);
    const request = repo.latestRequestForEvent(e.id);

    if (c.req.query("done") || state.state === "allowed") {
      const readyAt = state.state === "allowed" ? state.readyAt : Date.now();
      return c.html(<DonePage event={e} vlan={vlan} ret={ret} readyAt={readyAt} denied={state.state === "denied"} />);
    }

    const { queries } = await recentLogged(e.createdAt - 5 * 60_000);
    const active = repo.activeOverrides();
    const siblings = siblingDomains(queries, e.clientIp, e.createdAt, e.domain).filter(
      (d) => !active.some((o) => o.kind === "allow" && o.vlanId === e.vlanId && domainCovers(o.domain!, d)),
    );
    const allowDurations = [
      ...(policy.can(u, scope, "allowTemporary") ? policy.durations(scope, "allowTemporary") : []),
      ...(policy.can(u, scope, "allowPermanent") ? ["permanent"] : []),
    ];
    const pauseDurations = policy.can(u, scope, "pause") ? policy.durations(scope, "pause") : [];
    const retQs = ret ? `?return=${encodeURIComponent(ret)}` : "";

    return c.html(
      <Layout title={`Unblock ${e.domain}?`} nav={<Nav user={u} />}>
        <p class="muted small">Block code {e.code}</p>
        <h1 class="domain">{e.domain}</h1>
        <p class="muted small">
          {vlan.name} · {e.clientName ?? e.clientIp} · {fmtAgo(e.createdAt)}
        </p>
        {request?.status === "pending" ? (
          <p class="notice small">
            Requested {fmtAgo(request.createdAt)}
            {request.note ? <>: “{request.note}”</> : "."}
          </p>
        ) : null}

        {allowDurations.length ? (
          <section class="card">
            <h2>Allow on {vlan.name}</h2>
            <form method="post" action={`/r/${e.code}/allow${retQs}`} class="stack">
              <label class="check">
                <input type="checkbox" checked disabled />
                <span class="domain">{e.domain}</span>
              </label>
              {siblings.length ? (
                <>
                  <p class="muted small" style="margin-bottom:0">
                    Also blocked on this device around the same time (sites often need these too):
                  </p>
                  {siblings.map((d) => (
                    <label class="check">
                      <input type="checkbox" name="extra" value={d} />
                      <span class="domain">{d}</span>
                    </label>
                  ))}
                </>
              ) : null}
              <div class="row">
                {allowDurations.map((d) => (
                  <button class="primary" type="submit" name="duration" value={d}>
                    {durationLabel(d)}
                  </button>
                ))}
              </div>
            </form>
          </section>
        ) : null}

        {pauseDurations.length ? (
          <section class="card">
            <h2>Pause all blocking on {vlan.name}</h2>
            <form method="post" action={`/r/${e.code}/pause${retQs}`} class="row">
              {pauseDurations.map((d) => (
                <button type="submit" name="duration" value={d}>
                  {durationLabel(d)}
                </button>
              ))}
            </form>
          </section>
        ) : null}

        {request?.status === "pending" ? (
          <form method="post" action={`/r/${e.code}/deny`}>
            <button class="danger" type="submit">Decline request</button>
          </form>
        ) : null}
      </Layout>,
    );
  });

  const loadOwnedEvent = (c: Context<AdminEnv>) => {
    const code = normalizeCode(c.req.param("code") ?? "");
    const e = code ? repo.eventByCode(code) : undefined;
    if (!e || e.expiresAt < Date.now()) throw new ActionError(404, "Code not found or expired");
    return e;
  };

  const doneRedirect = (c: Context<AdminEnv>, e: BlockEvent) => {
    const ret = validReturn(c.req.query("return"), e);
    return c.redirect(`/r/${e.code}?done=1${ret ? `&return=${encodeURIComponent(ret)}` : ""}`, 303);
  };

  pages.post("/r/:code/allow", async (c) => {
    const u = currentUser(c)!;
    try {
      const e = loadOwnedEvent(c);
      const form = await c.req.parseBody({ all: true });
      const extra = ([] as unknown[]).concat(form.extra ?? []).map(String);
      const duration = String(form.duration ?? "");
      const pending = repo.pendingRequestForEvent(e.id);
      if (pending) service.approveRequest(u, pending.id, { action: "allow", duration, extraDomains: extra });
      else
        service.allow(u, {
          scope: { kind: "vlan", vlanId: e.vlanId },
          domains: [e.domain, ...extra],
          duration,
          blockEventId: e.id,
        });
      return doneRedirect(c, e);
    } catch (err) {
      return fail(c, err);
    }
  });

  pages.post("/r/:code/pause", async (c) => {
    const u = currentUser(c)!;
    try {
      const e = loadOwnedEvent(c);
      const duration = String((await c.req.parseBody()).duration ?? "");
      const pending = repo.pendingRequestForEvent(e.id);
      if (pending) service.approveRequest(u, pending.id, { action: "pause", duration });
      else service.pause(u, { scope: { kind: "vlan", vlanId: e.vlanId }, duration, blockEventId: e.id });
      return doneRedirect(c, e);
    } catch (err) {
      return fail(c, err);
    }
  });

  pages.post("/r/:code/deny", (c) => {
    const u = currentUser(c)!;
    try {
      const e = loadOwnedEvent(c);
      const pending = repo.pendingRequestForEvent(e.id);
      if (!pending) throw new ActionError(409, "No pending request for this block");
      service.denyRequest(u, pending.id);
      return c.redirect("/", 303);
    } catch (err) {
      return fail(c, err);
    }
  });

  // ---------- dashboard actions ----------

  pages.post("/allow", async (c) => {
    const u = currentUser(c)!;
    const form = await c.req.parseBody();
    const scope: Scope =
      form.vlanId === "global" ? { kind: "global" } : { kind: "vlan", vlanId: String(form.vlanId ?? "") };
    try {
      service.allow(u, { scope, domains: [String(form.domain ?? "")], duration: String(form.duration ?? "") });
      return c.redirect("/", 303);
    } catch (err) {
      return fail(c, err);
    }
  });

  pages.post("/pause", async (c) => {
    const u = currentUser(c)!;
    const form = await c.req.parseBody();
    const scope: Scope =
      form.scope === "global" ? { kind: "global" } : { kind: "vlan", vlanId: String(form.scope ?? "") };
    try {
      service.pause(u, { scope, duration: String(form.duration ?? "") });
      return c.redirect("/", 303);
    } catch (err) {
      return fail(c, err);
    }
  });

  pages.post("/overrides/:id/revoke", (c) => {
    const u = currentUser(c)!;
    try {
      service.revoke(u, Number(c.req.param("id")));
      return c.redirect("/", 303);
    } catch (err) {
      return fail(c, err);
    }
  });

  app.route("/", pages);

  // ---------- components ----------

  function PauseRow(props: { label: string; scope: Scope; active: Override | undefined; user: User }) {
    const { scope, active, user } = props;
    const durations = policy.can(user, scope, "pause") ? policy.durations(scope, "pause") : [];
    const scopeValue = scope.kind === "global" ? "global" : scope.vlanId;
    return (
      <li class="row between">
        <div>
          <strong>{props.label}</strong>{" "}
          {active ? (
            <span class="chip warn">paused · {formatRemaining(active.expiresAt)}</span>
          ) : (
            <span class="chip ok">blocking</span>
          )}
          {active ? <div class="muted small">by {active.createdBy}</div> : null}
        </div>
        {active ? (
          service.canRevoke(user, active) ? (
            <RevokeButton id={active.id} label="Resume" />
          ) : null
        ) : durations.length ? (
          <form method="post" action="/pause" class="row">
            <input type="hidden" name="scope" value={scopeValue} />
            <select name="duration" aria-label="Pause duration">
              {durations.map((d) => (
                <option value={d}>{durationLabel(d)}</option>
              ))}
            </select>
            <button type="submit">Pause</button>
          </form>
        ) : null}
      </li>
    );
  }

  return app;
}

function validReturn(ret: string | undefined, e: BlockEvent): string | null {
  if (!ret) return null;
  try {
    const u = new URL(ret);
    // Only send people back to the site that was blocked (no open redirect).
    if ((u.protocol === "http:" || u.protocol === "https:") && u.hostname.toLowerCase() === e.domain) return u.href;
  } catch {
    /* ignore */
  }
  return null;
}

function Nav(props: { user: User }) {
  return (
    <header class="top">
      <a href="/">Blocks</a>
      <form method="post" action="/auth/logout" class="row">
        <span class="muted small">{principalLabel(props.user)}</span>
        <button type="submit">Sign out</button>
      </form>
    </header>
  );
}

function RevokeButton(props: { id: number; label: string }) {
  return (
    <form method="post" action={`/overrides/${props.id}/revoke`}>
      <button type="submit">{props.label}</button>
    </form>
  );
}

function Message(props: { title: string; body: string; back?: string }) {
  return (
    <Layout title={props.title}>
      <h1>{props.title}</h1>
      <p>{props.body}</p>
      {props.back ? <a class="btn" href={props.back}>Back</a> : null}
    </Layout>
  );
}

function DonePage(props: { event: BlockEvent; vlan: Vlan; ret: string | null; readyAt: number; denied: boolean }) {
  const { event, ret } = props;
  const script = ret
    ? `(() => {
  const el = document.getElementById('countdown'), until = ${props.readyAt}, ret = ${JSON.stringify(ret)};
  const tick = () => {
    const s = Math.ceil((until - Date.now()) / 1000);
    if (s <= 0) { location.replace(ret); return; }
    el.textContent = 'Taking you back in ' + s + 's…';
    setTimeout(tick, 500);
  };
  tick();
})();`
    : undefined;
  return (
    <Layout title={`Unblocked ${event.domain}`} script={script}>
      <h1 class="domain">{event.domain}</h1>
      {props.denied ? (
        <p class="status danger">Request declined.</p>
      ) : (
        <>
          <p class="status ok">Unblocked on {props.vlan.name}.</p>
          {ret ? (
            <p id="countdown" class="muted" />
          ) : (
            <p class="muted">The blocked device will continue automatically within a few seconds.</p>
          )}
        </>
      )}
      <a class="btn" href="/">Dashboard</a>
    </Layout>
  );
}

function AuditCard(props: { entries: ReturnType<Deps["repo"]["recentAudit"]> }) {
  return (
    <section class="card">
      <h2>Activity</h2>
      <ul class="list">
        {props.entries.map((a) => (
          <li class="small">
            <span class="muted">{fmtAgo(a.ts)}</span> · <strong>{a.actor}</strong> · {a.action}{" "}
            <span class="domain muted">{String(a.details.domain ?? a.details.vlanId ?? a.details.scope ?? "")}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

