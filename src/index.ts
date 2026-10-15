import { serve } from "@hono/node-server";
import { join } from "node:path";
import { OidcClient } from "./auth/oidc.js";
import { Sealer } from "./auth/session.js";
import { loadConfig } from "./config.js";
import { openDb } from "./db/db.js";
import { Repo } from "./db/repo.js";
import { log } from "./lib/log.js";
import { Policy } from "./policy.js";
import { Reconciler } from "./reconciler.js";
import { Service } from "./service.js";
import { TechnitiumClient } from "./technitium/client.js";
import { BlockLog } from "./technitium/logs.js";
import { createAdminApp } from "./web/admin/app.js";
import { createBlockApp } from "./web/block/app.js";
import type { Deps } from "./web/context.js";
import { Events } from "./webhooks.js";

const config = loadConfig();
const { policy: pc, secrets } = config;

const repo = new Repo(openDb(join(config.dataDir, "blocks.db")));
const policy = new Policy(pc);
const client = new TechnitiumClient(pc.technitium.url, secrets.technitiumToken);
const reconciler = new Reconciler({
  repo,
  client,
  policy,
  log,
  appName: pc.technitium.advancedBlockingAppName,
  pauseBuiltIn: pc.technitium.pauseBuiltInBlocking,
});
const events = new Events(pc.webhooks, secrets.webhookSecrets, log);
const service = new Service(repo, policy, reconciler, events, { blockEventTtlMinutes: pc.blockEventTtlMinutes });
const publicUrl = pc.admin.publicUrl.replace(/\/$/, "");

const deps: Deps = {
  config,
  policy,
  repo,
  service,
  reconciler,
  events,
  log,
  blockLog: new BlockLog(client, {
    technitiumUrl: pc.technitium.url,
    dnsServer: pc.technitium.dnsServer,
    queryLogger: pc.technitium.queryLogger,
    log,
  }),
  oidc: new OidcClient({
    issuer: pc.oidc.issuer,
    clientId: pc.oidc.clientId,
    clientSecret: secrets.oidcClientSecret,
    redirectUri: `${publicUrl}/auth/callback`,
    scopes: pc.oidc.scopes,
    log,
  }),
  sealer: new Sealer(secrets.sessionSecret),
};

const blockServer = serve({ fetch: createBlockApp(deps).fetch, port: pc.blockPage.port, hostname: "::" }, (i) =>
  log.info("block page listening", { port: i.port }),
);
const adminServer = serve({ fetch: createAdminApp(deps).fetch, port: pc.admin.port, hostname: "::" }, (i) =>
  log.info("admin listening", { port: i.port, publicUrl }),
);

reconciler.start();
const pruneTimer = setInterval(() => repo.prune(Date.now() - 7 * 86_400_000), 3_600_000);

function shutdown() {
  log.info("shutting down");
  reconciler.stop();
  clearInterval(pruneTimer);
  blockServer.close();
  adminServer.close();
  repo.db.close();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
