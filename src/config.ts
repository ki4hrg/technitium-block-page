import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { isValidCidr } from "./lib/cidr.js";
import { isValidDuration } from "./lib/duration.js";

const duration = z.string().refine(isValidDuration, { message: "duration must be like 15m, 1h, 2d, today or permanent" });

/**
 * Who may perform an action. "none" = anyone on the VLAN, straight from the block page.
 * Otherwise the actor must match one of the listed users or groups (OIDC or integration users).
 */
const requirement = z.union([
  z.literal("none"),
  z.object({
    users: z.array(z.string()).default([]),
    groups: z.array(z.string()).default([]),
  }),
]);

const timedAction = z.object({
  require: requirement,
  durations: z.array(duration).min(1),
});

const permanentAction = z.object({ require: requirement });

const vlanSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]+$/i),
  name: z.string(),
  cidrs: z.array(z.string().refine(isValidCidr, { message: "invalid CIDR" })).min(1),
  /** Advanced Blocking group this VLAN maps to. */
  group: z.string(),
  /** Show which VLAN/policy blocked the request on the block page. */
  showDetails: z.boolean().default(true),
  actions: z
    .object({
      allowTemporary: timedAction.optional(),
      allowPermanent: permanentAction.optional(),
      pause: timedAction.optional(),
      requestUnblock: z.object({ enabled: z.boolean().default(true) }).optional(),
    })
    .default({}),
});

const integrationSchema = z.object({
  /** Env var holding the bearer token this integration presents. */
  tokenEnv: z.string(),
  /**
   * Users the integration may act on behalf of (e.g. Home Assistant user names or ids),
   * and the groups they are treated as members of. Unlisted actors get no permissions.
   */
  users: z.record(z.string(), z.object({ groups: z.array(z.string()).default([]) })).default({}),
});

const webhookSchema = z.object({
  url: z.string().url(),
  /** Event types to send; empty = all. */
  events: z.array(z.string()).default([]),
  /** Env var with a secret sent as `X-Webhook-Secret`. */
  secretEnv: z.string().optional(),
});

export const configSchema = z.object({
  technitium: z.object({
    url: z.string().url(),
    /** DNS server used for PTR lookups; defaults to the host of `url`. */
    dnsServer: z.string().optional(),
    advancedBlockingAppName: z.string().default("Advanced Blocking"),
    /** Query logger app; auto-detected via /api/apps/list when omitted. */
    queryLogger: z.object({ name: z.string(), classPath: z.string() }).optional(),
    /** Also pause Technitium's built-in blocking during a global pause. */
    pauseBuiltInBlocking: z.boolean().default(true),
  }),
  blockPage: z.object({
    /** The custom blocking address configured on every Advanced Blocking group. */
    ip: z.string(),
    port: z.number().int().default(80),
    /** Hostnames that show the "recent blocks from this device" page instead of a block page. */
    hostnames: z.array(z.string()).default([]),
  }),
  admin: z.object({
    /** External HTTPS URL of the admin UI (behind the reverse proxy). */
    publicUrl: z.string().url(),
    port: z.number().int().default(3000),
  }),
  oidc: z.object({
    issuer: z.string().url(),
    clientId: z.string(),
    scopes: z.string().default("openid profile email groups"),
  }),
  vlans: z.array(vlanSchema).min(1),
  global: z
    .object({
      pause: timedAction.optional(),
      allowTemporary: timedAction.optional(),
      allowPermanent: permanentAction.optional(),
    })
    .default({}),
  /** Users or groups that can see and act on everything in the admin UI (e.g. revoke any override). */
  admins: z.object({ users: z.array(z.string()).default([]), groups: z.array(z.string()).default([]) }).default({
    users: [],
    groups: [],
  }),
  integrations: z.record(z.string(), integrationSchema).default({}),
  webhooks: z.array(webhookSchema).default([]),
  blockEventTtlMinutes: z.number().int().positive().default(60),
});

export type PolicyConfig = z.infer<typeof configSchema>;
export type Vlan = z.infer<typeof vlanSchema>;
export type Requirement = z.infer<typeof requirement>;
export type TimedAction = z.infer<typeof timedAction>;

export interface Secrets {
  technitiumToken: string;
  oidcClientSecret: string;
  sessionSecret: string;
  integrationTokens: Map<string, string>; // token -> integration id
  webhookSecrets: Map<string, string>; // url -> secret
}

export interface AppConfig {
  policy: PolicyConfig;
  secrets: Secrets;
  dataDir: string;
}

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v) throw new Error(`Missing required environment variable ${name}`);
  return v;
}

export function parsePolicy(raw: unknown): PolicyConfig {
  const policy = configSchema.parse(raw);
  const ids = new Set<string>();
  for (const v of policy.vlans) {
    if (ids.has(v.id)) throw new Error(`Duplicate VLAN id: ${v.id}`);
    ids.add(v.id);
  }
  return policy;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const path = env.POLICY_FILE ?? "config/policy.yaml";
  const policy = parsePolicy(parseYaml(readFileSync(path, "utf8")));

  const integrationTokens = new Map<string, string>();
  for (const [id, integration] of Object.entries(policy.integrations)) {
    const token = requireEnv(env, integration.tokenEnv);
    if (token.length < 24) throw new Error(`${integration.tokenEnv} must be at least 24 characters`);
    integrationTokens.set(token, id);
  }
  const webhookSecrets = new Map<string, string>();
  for (const hook of policy.webhooks) {
    if (hook.secretEnv) webhookSecrets.set(hook.url, requireEnv(env, hook.secretEnv));
  }

  const sessionSecret = requireEnv(env, "SESSION_SECRET");
  if (sessionSecret.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters");

  return {
    policy,
    dataDir: env.DATA_DIR ?? "data",
    secrets: {
      technitiumToken: requireEnv(env, "TECHNITIUM_TOKEN"),
      oidcClientSecret: requireEnv(env, "OIDC_CLIENT_SECRET"),
      sessionSecret,
      integrationTokens,
      webhookSecrets,
    },
  };
}
