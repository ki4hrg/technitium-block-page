import { Hono, type Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import QRCode from "qrcode";
import { raw } from "hono/html";
import type { BlockEvent } from "../../db/repo.js";
import { durationLabel } from "../../lib/duration.js";
import { normalizeIp } from "../../lib/cidr.js";
import type { Principal, Scope } from "../../policy.js";
import { ActionError } from "../../service.js";
import type { Deps } from "../context.js";
import { fmtAgo, Layout } from "../layout.js";

// The block listener. Every hostname Technitium blocks resolves here, so all of our own
// endpoints live under /_tbp/ to stay out of the way of whatever path was requested.
// This listener never does OIDC: anything needing a login links to the admin host.

type GetIp = (c: Context) => string;

const defaultGetIp: GetIp = (c) => getConnInfo(c).remote.address ?? "";

export function createBlockApp(deps: Deps, getIp: GetIp = defaultGetIp) {
  const { policy, service, repo, config } = deps;
  const publicUrl = config.policy.admin.publicUrl.replace(/\/$/, "");
  const ownHosts = new Set([config.policy.blockPage.ip, ...config.policy.blockPage.hostnames].map((h) => h.toLowerCase()));
  const app = new Hono();

  const principalFor = (c: Context): Principal => {
    const ip = normalizeIp(getIp(c));
    return { kind: "network", ip, vlanId: policy.vlanForIp(ip)?.id ?? null };
  };

  /** Load the event for a code, but only if it belongs to the device asking. */
  const ownEvent = (c: Context, code: string | undefined): BlockEvent | null => {
    const e = code ? repo.eventByCode(code) : undefined;
    if (!e || e.clientIp !== normalizeIp(getIp(c))) return null;
    return e;
  };

  app.get("/_tbp/status/:code", (c) => {
    const e = ownEvent(c, c.req.param("code"));
    if (!e) return c.json({ error: "not found" }, 404);
    return c.json({ ...service.eventState(e), now: Date.now() });
  });

  app.post("/_tbp/act", async (c) => {
    const form = await c.req.parseBody();
    const e = ownEvent(c, String(form.code ?? ""));
    if (!e) return c.text("Unknown or expired block code", 404);
    const p = principalFor(c);
    const scope: Scope = form.scope === "global" ? { kind: "global" } : { kind: "vlan", vlanId: e.vlanId };
    const duration = String(form.duration ?? "");
    try {
      if (form.action === "pause") service.pause(p, { scope, duration, blockEventId: e.id });
      else service.allow(p, { scope, domains: [e.domain], duration, blockEventId: e.id });
    } catch (err) {
      if (err instanceof ActionError) return c.text(err.message, err.status);
      throw err;
    }
    return c.redirect(e.url, 303);
  });

  app.post("/_tbp/request", async (c) => {
    const form = await c.req.parseBody();
    const e = ownEvent(c, String(form.code ?? ""));
    if (!e) return c.text("Unknown or expired block code", 404);
    try {
      service.requestUnblock(principalFor(c), e, String(form.note ?? ""));
    } catch (err) {
      if (err instanceof ActionError) return c.text(err.message, err.status);
      throw err;
    }
    return c.redirect(e.url, 303);
  });

  app.all("*", async (c) => {
    if (c.req.method !== "GET" && c.req.method !== "HEAD") return c.text("Blocked by network policy", 403);
    const host = (c.req.header("host") ?? "").replace(/:\d+$/, "").toLowerCase();
    const p = principalFor(c) as Extract<Principal, { kind: "network" }>;

    if (!host || ownHosts.has(host)) return c.html(await deviceHome(c, p));

    // Only real page loads get a block page; images/scripts/XHR just fail fast.
    if (!(c.req.header("accept") ?? "").includes("text/html")) return c.text("Blocked by network policy", 403);

    const url = `http://${c.req.header("host")}${c.req.path}${new URL(c.req.url).search}`;
    const clientName = await deps.blockLog.clientName(p.ip);
    const event = service.recordBlock({ clientIp: p.ip, clientName, host, url });
    c.header("Cache-Control", "no-store");
    if (!event) return c.html(unknownNetworkPage(host, p.ip), 403);
    return c.html(await blockPage(event, p), 403);
  });

  async function blockPage(e: BlockEvent, p: Extract<Principal, { kind: "network" }>) {
    const vlan = policy.vlan(e.vlanId)!;
    const state = service.eventState(e);
    const vlanScope: Scope = { kind: "vlan", vlanId: e.vlanId };
    const selfAllow = [
      ...(policy.can(p, vlanScope, "allowTemporary") ? policy.durations(vlanScope, "allowTemporary") : []),
      ...(policy.can(p, vlanScope, "allowPermanent") ? ["permanent"] : []),
    ];
    const selfPause = policy.can(p, vlanScope, "pause") ? policy.durations(vlanScope, "pause") : [];
    const needsApproval =
      (vlan.actions.allowTemporary && !policy.can(p, vlanScope, "allowTemporary")) ||
      (vlan.actions.allowPermanent && !policy.can(p, vlanScope, "allowPermanent")) ||
      (vlan.actions.pause && !policy.can(p, vlanScope, "pause"));
    const canRequest = policy.canRequest(p, e.vlanId);
    const approveUrl = `${publicUrl}/r/${e.code}`;
    const sameDeviceUrl = `${approveUrl}?return=${encodeURIComponent(e.url)}`;
    const qr = needsApproval ? await QRCode.toString(approveUrl, { type: "svg", margin: 0 }) : "";

    const script = `
(() => {
  const url = ${JSON.stringify(e.url)}, code = ${JSON.stringify(e.code)};
  const el = document.getElementById('state');
  let skew = 0;
  async function poll() {
    try {
      const r = await fetch('/_tbp/status/' + code, { cache: 'no-store' });
      if (r.ok) {
        const s = await r.json();
        skew = s.now - Date.now();
        if (s.state === 'allowed') {
          const wait = Math.max(0, Math.ceil((s.readyAt - (Date.now() + skew)) / 1000));
          if (wait === 0) { el.textContent = 'Unblocked — loading the site…'; location.replace(url); return; }
          el.textContent = 'Unblocked — your device will pick up the change in ' + wait + 's…';
          el.className = 'status ok';
        } else if (s.state === 'requested') {
          el.textContent = 'Request sent — waiting for approval…'; el.className = 'status warn';
        } else if (s.state === 'denied') {
          el.textContent = 'Request declined' + (s.by ? ' by ' + s.by : '') + '.'; el.className = 'status danger';
        }
      }
    } catch {}
    setTimeout(poll, 2500);
  }
  poll();
})();`;

    return (
      <Layout title={`Blocked: ${e.domain}`} script={script}>
        <p class="muted small">This site is blocked on this network</p>
        <h1 class="domain" style="font-size:1.5rem">{e.domain}</h1>
        {vlan.showDetails ? (
          <p class="muted small">
            {vlan.name} network · {e.clientName ?? e.clientIp}
          </p>
        ) : null}
        <p id="state" class={`status ${stateClass(state.state)}`}>
          {stateText(state)}
        </p>

        {selfAllow.length || selfPause.length ? (
          <section class="card stack">
            <h2>Unblock</h2>
            {selfAllow.length ? (
              <div class="row">
                <span class="muted small">Allow {e.domain}:</span>
                {selfAllow.map((d) => (
                  <ActForm code={e.code} action="allow" duration={d} />
                ))}
              </div>
            ) : null}
            {selfPause.length ? (
              <div class="row">
                <span class="muted small">Pause all blocking on {vlan.name}:</span>
                {selfPause.map((d) => (
                  <ActForm code={e.code} action="pause" duration={d} />
                ))}
              </div>
            ) : null}
          </section>
        ) : null}

        {needsApproval ? (
          <section class="card">
            <h2>Need a grown-up?</h2>
            <div class="row" style="gap:20px;align-items:flex-start">
              <div class="qr">{raw(qr)}</div>
              <div class="stack">
                <p class="muted small" style="margin:0">Scan with another phone, or enter this code at</p>
                <p class="small" style="margin:0">
                  <strong>{publicUrl.replace(/^https?:\/\//, "")}</strong>
                </p>
                <div class="code">{e.code}</div>
                <a class="btn" href={sameDeviceUrl}>
                  Sign in on this device
                </a>
              </div>
            </div>
          </section>
        ) : null}

        {canRequest && state.state === "blocked" ? (
          <section class="card">
            <h2>Ask to unblock</h2>
            <form method="post" action="/_tbp/request" class="stack">
              <input type="hidden" name="code" value={e.code} />
              <textarea name="note" maxlength={500} placeholder="Why do you need this site? (optional)" />
              <button class="primary" type="submit">
                Send request
              </button>
            </form>
          </section>
        ) : null}

        <p class="muted small">
          Seeing a security warning instead of this page on other sites? Open{" "}
          {config.policy.blockPage.hostnames[0] ? `http://${config.policy.blockPage.hostnames[0]}` : publicUrl} to see
          what was blocked.
        </p>
      </Layout>
    );
  }

  async function deviceHome(c: Context, p: Extract<Principal, { kind: "network" }>) {
    const vlan = p.vlanId ? policy.vlan(p.vlanId) : undefined;
    const since = Date.now() - 2 * 3_600_000;
    const events = repo.recentEvents({ since, clientIp: p.ip, limit: 20 });
    let logged: { domain: string; at: number }[] = [];
    try {
      const q = await deps.blockLog.recentBlocked({ since: new Date(since), clientIp: p.ip, limit: 200 });
      const seen = new Map<string, number>();
      for (const r of q) seen.set(r.domain, Math.max(seen.get(r.domain) ?? 0, r.timestamp));
      logged = [...seen].map(([domain, at]) => ({ domain, at })).sort((a, b) => b.at - a.at).slice(0, 30);
    } catch (err) {
      deps.log.warn("could not read query logs", { error: String(err) });
    }
    c.header("Cache-Control", "no-store");
    return (
      <Layout title="Blocked on this device">
        <h1>Blocked on this device</h1>
        <p class="muted small">
          {vlan ? `${vlan.name} network · ` : ""}
          {p.ip}
        </p>
        {events.length ? (
          <section class="card">
            <h2>Block pages you've seen</h2>
            <ul class="list">
              {events.map((e) => (
                <li class="row between">
                  <span class="domain">{e.domain}</span>
                  <a class="btn" href={e.url}>
                    Open ({e.code})
                  </a>
                </li>
              ))}
            </ul>
          </section>
        ) : null}
        <section class="card">
          <h2>Recently blocked lookups</h2>
          <p class="muted small">
            Includes apps and secure (https) sites that couldn't show a block page. Open one to get an unblock code.
          </p>
          {logged.length ? (
            <ul class="list">
              {logged.map((l) => (
                <li class="row between">
                  <span class="domain">{l.domain}</span>
                  <span class="row">
                    <span class="muted small">{fmtAgo(l.at)}</span>
                    <a class="btn" href={`http://${l.domain}/`}>
                      Open
                    </a>
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p class="muted">Nothing blocked in the last two hours.</p>
          )}
        </section>
      </Layout>
    );
  }

  return app;
}

function ActForm(props: { code: string; action: "allow" | "pause"; duration: string }) {
  return (
    <form method="post" action="/_tbp/act">
      <input type="hidden" name="code" value={props.code} />
      <input type="hidden" name="action" value={props.action} />
      <input type="hidden" name="duration" value={props.duration} />
      <button type="submit" class={props.action === "allow" ? "primary" : ""}>
        {durationLabel(props.duration)}
      </button>
    </form>
  );
}

function stateClass(s: string) {
  return s === "allowed" ? "ok" : s === "requested" ? "warn" : s === "denied" ? "danger" : "";
}

function stateText(s: ReturnType<Deps["service"]["eventState"]>) {
  switch (s.state) {
    case "allowed":
      return "Unblocked — waiting for your device to pick up the change…";
    case "requested":
      return "Request sent — waiting for approval…";
    case "denied":
      return `Request declined${s.by ? ` by ${s.by}` : ""}.`;
    default:
      return "";
  }
}

function unknownNetworkPage(host: string, ip: string) {
  return (
    <Layout title={`Blocked: ${host}`}>
      <h1 class="domain">{host}</h1>
      <p>This site is blocked on this network.</p>
      <p class="muted small">Your device ({ip}) isn't on a network with unblock options.</p>
    </Layout>
  );
}
