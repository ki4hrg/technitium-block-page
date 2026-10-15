import { Sealer, type SessionUser } from "../src/auth/session.js";
import { parsePolicy, type AppConfig, type PolicyConfig } from "../src/config.js";
import { openDb } from "../src/db/db.js";
import { Repo } from "../src/db/repo.js";
import { silentLog } from "../src/lib/log.js";
import { Policy } from "../src/policy.js";
import { Reconciler } from "../src/reconciler.js";
import { Service } from "../src/service.js";
import type { AdvancedBlockingConfig } from "../src/technitium/advancedBlocking.js";
import { TechnitiumClient, type QueryLogEntry } from "../src/technitium/client.js";
import { BlockLog } from "../src/technitium/logs.js";
import { createAdminApp } from "../src/web/admin/app.js";
import { SESSION_COOKIE } from "../src/web/admin/auth.js";
import { createBlockApp } from "../src/web/block/app.js";
import type { Deps } from "../src/web/context.js";
import { Events, type OutboundEvent } from "../src/webhooks.js";

export const PUBLIC_URL = "https://blocks.example.test";
export const HA_TOKEN = "ha-token-0123456789abcdefghijklmnop";

export function testPolicy(): PolicyConfig {
  return parsePolicy({
    technitium: { url: "http://technitium.test:5380", queryLogger: { name: "Query Logs (Sqlite)", classPath: "QueryLogsSqlite.App" } },
    blockPage: { ip: "10.0.0.250", hostnames: ["blocked.home.arpa"] },
    admin: { publicUrl: PUBLIC_URL },
    oidc: { issuer: "https://id.example.test", clientId: "blocks" },
    admins: { users: ["john"] },
    vlans: [
      {
        id: "trusted",
        name: "Main",
        cidrs: ["10.0.10.0/24"],
        group: "trusted",
        actions: {
          allowTemporary: { require: "none", durations: ["15m", "1h"] },
          allowPermanent: { require: "none" },
          pause: { require: "none", durations: ["15m"] },
        },
      },
      {
        id: "kids",
        name: "Kids",
        cidrs: ["10.0.30.0/24"],
        group: "kids",
        actions: {
          requestUnblock: { enabled: true },
          allowTemporary: { require: { groups: ["parents", "grandparents"] }, durations: ["15m", "1h", "today"] },
          allowPermanent: { require: { groups: ["parents"] } },
          pause: { require: { users: ["john"] }, durations: ["30m"] },
        },
      },
    ],
    global: { pause: { require: { groups: ["admins"] }, durations: ["1h"] } },
    integrations: {
      homeassistant: { tokenEnv: "HA_API_TOKEN", users: { grandma: { groups: ["grandparents"] }, john: {} } },
    },
  });
}

/** In-memory stand-in for the Technitium HTTP API. */
export class FakeTechnitium {
  appConfig: AdvancedBlockingConfig = {
    enableBlocking: true,
    blockingAnswerTtl: 10,
    networkGroupMap: { "10.0.30.0/24": "kids", "10.0.10.0/24": "trusted" },
    groups: [
      { name: "trusted", enableBlocking: true, allowed: [], blockingAddresses: ["10.0.0.250"] },
      { name: "kids", enableBlocking: true, allowed: ["manual.example"], blockingAddresses: ["10.0.0.250"] },
    ],
  };
  settings = { enableBlocking: true } as { enableBlocking: boolean; temporaryDisableBlockingTill?: string };
  logs: QueryLogEntry[] = [];
  writes = 0;
  calls: string[] = [];
  failing = false;

  fetch: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    this.calls.push(url.pathname);
    if (this.failing) return new Response("down", { status: 500 });
    const ok = (response: unknown) => new Response(JSON.stringify({ status: "ok", response }));
    switch (url.pathname) {
      case "/api/apps/config/get":
        return ok({ config: JSON.stringify(this.appConfig) });
      case "/api/apps/config/set": {
        const body = new URLSearchParams(String(init?.body));
        this.appConfig = JSON.parse(body.get("config")!) as AdvancedBlockingConfig;
        this.writes++;
        return ok({});
      }
      case "/api/settings/get":
        return ok(this.settings);
      case "/api/settings/set":
        this.settings.enableBlocking = url.searchParams.get("enableBlocking") === "true";
        return ok(this.settings);
      case "/api/settings/temporaryDisableBlocking": {
        const till = new Date(Date.now() + Number(url.searchParams.get("minutes")) * 60_000).toISOString();
        this.settings = { enableBlocking: false, temporaryDisableBlockingTill: till };
        return ok({ temporaryDisableBlockingTill: till });
      }
      case "/api/logs/query": {
        const ip = url.searchParams.get("clientIpAddress");
        const entries = this.logs.filter((e) => !ip || e.clientIpAddress === ip);
        return ok({ pageNumber: 1, totalPages: 1, totalEntries: entries.length, entries });
      }
      default:
        return new Response(JSON.stringify({ status: "error", errorMessage: `unhandled ${url.pathname}` }));
    }
  };

  logBlocked(clientIp: string, qname: string, at = Date.now()) {
    this.logs.unshift({
      rowNumber: this.logs.length + 1,
      timestamp: new Date(at).toISOString(),
      clientIpAddress: clientIp,
      protocol: "Udp",
      responseType: "Blocked",
      rcode: "NoError",
      qname,
      qtype: "A",
      qclass: "IN",
      answer: "10.0.0.250",
    });
  }

  group(name: string) {
    return this.appConfig.groups!.find((g) => g.name === name)!;
  }
}

export function createHarness() {
  const policyConfig = testPolicy();
  const config: AppConfig = {
    policy: policyConfig,
    dataDir: ":memory:",
    secrets: {
      technitiumToken: "t",
      oidcClientSecret: "s",
      sessionSecret: "x".repeat(40),
      integrationTokens: new Map([[HA_TOKEN, "homeassistant"]]),
      webhookSecrets: new Map(),
    },
  };
  const technitium = new FakeTechnitium();
  const client = new TechnitiumClient(policyConfig.technitium.url, "t", technitium.fetch);
  const repo = new Repo(openDb(":memory:"));
  const policy = new Policy(policyConfig);
  const reconciler = new Reconciler({
    repo,
    client,
    policy,
    log: silentLog,
    appName: "Advanced Blocking",
    pauseBuiltIn: true,
  });
  const events = new Events([], new Map(), silentLog);
  const emitted: OutboundEvent[] = [];
  events.subscribe((e) => emitted.push(e));
  const service = new Service(repo, policy, reconciler, events, { blockEventTtlMinutes: 60 });
  const sealer = new Sealer(config.secrets.sessionSecret);
  const blockLog = new BlockLog(client, {
    technitiumUrl: policyConfig.technitium.url,
    queryLogger: policyConfig.technitium.queryLogger,
    log: silentLog,
  });
  // No real DNS in tests.
  blockLog.clientName = async () => null;

  const deps: Deps = {
    config,
    policy,
    repo,
    service,
    reconciler,
    events,
    blockLog,
    oidc: {
      startLogin: async () => ({ url: "https://id.example.test/authorize", state: "st", verifier: "v" }),
      finishLogin: async () => ({ sub: "p1", username: "jane", name: "Jane", groups: ["parents"] }),
    },
    sealer,
    log: silentLog,
  };

  let clientIp = "10.0.30.5";
  const blockApp = createBlockApp(deps, () => clientIp);
  const adminApp = createAdminApp(deps);

  return {
    deps,
    technitium,
    reconciler,
    repo,
    service,
    emitted,
    setClientIp: (ip: string) => (clientIp = ip),
    /** Request against the block listener as a device. */
    block: (path: string, init: RequestInit & { host?: string } = {}) =>
      blockApp.request(`http://${init.host ?? "youtube.com"}${path}`, {
        ...init,
        headers: { host: init.host ?? "youtube.com", accept: "text/html", ...(init.headers as Record<string, string>) },
      }),
    /** Request against the admin listener, optionally signed in. */
    admin: (path: string, init: RequestInit & { user?: SessionUser } = {}) => {
      const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
      if (init.user) headers.cookie = `${SESSION_COOKIE}=${sealer.seal(init.user, 3_600_000)}`;
      if (init.method && init.method !== "GET") headers.origin ??= PUBLIC_URL;
      return adminApp.request(`${PUBLIC_URL}${path}`, { ...init, headers });
    },
  };
}

export const JANE: SessionUser = { sub: "p1", username: "jane", name: "Jane", groups: ["parents"] };
export const JOHN: SessionUser = { sub: "j1", username: "john", name: "John", groups: [] };
export const KID_USER: SessionUser = { sub: "k1", username: "kid", name: "Kid", groups: ["kids"] };

export function form(data: Record<string, string | string[]>): RequestInit {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) for (const item of [v].flat()) body.append(k, item);
  return { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded" } };
}
