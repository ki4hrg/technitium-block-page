import type { AppConfig } from "../config.js";
import type { Repo } from "../db/repo.js";
import type { Logger } from "../lib/log.js";
import type { Policy } from "../policy.js";
import type { Reconciler } from "../reconciler.js";
import type { Service } from "../service.js";
import type { BlockLog } from "../technitium/logs.js";
import type { Events } from "../webhooks.js";
import type { OidcClient } from "../auth/oidc.js";
import type { Sealer } from "../auth/session.js";

export interface Deps {
  config: AppConfig;
  policy: Policy;
  repo: Repo;
  service: Service;
  reconciler: Pick<Reconciler, "status" | "trigger">;
  blockLog: Pick<BlockLog, "recentBlocked" | "clientName">;
  events: Events;
  oidc: Pick<OidcClient, "startLogin" | "finishLogin">;
  sealer: Sealer;
  log: Logger;
}
