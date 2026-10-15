import { lookup } from "node:dns/promises";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import type { Logger } from "../lib/log.js";
import { normalizeIp } from "../lib/cidr.js";
import type { TechnitiumClient } from "./client.js";

export interface BlockedQuery {
  timestamp: number;
  clientIp: string;
  domain: string;
  qtype: string;
}

export interface BlockedSummary {
  clientIp: string;
  clientName: string | null;
  domain: string;
  count: number;
  lastSeen: number;
}

const NAME_TTL_MS = 10 * 60_000;

/** Reads blocked queries from Technitium's query logger app and resolves client names via PTR. */
export class BlockLog {
  private loggerApp: Promise<{ name: string; classPath: string } | null> | null = null;
  private resolver: Promise<Resolver> | null = null;
  private names = new Map<string, { name: string | null; at: number }>();

  constructor(
    private readonly client: TechnitiumClient,
    private readonly opts: {
      technitiumUrl: string;
      dnsServer?: string;
      queryLogger?: { name: string; classPath: string };
      log: Logger;
    },
  ) {}

  private getLoggerApp() {
    if (this.opts.queryLogger) return Promise.resolve(this.opts.queryLogger);
    this.loggerApp ??= this.client
      .listApps()
      .then((apps) => {
        for (const app of apps) {
          const dnsApp = app.dnsApps.find((d) => d.isQueryLogger);
          if (dnsApp) return { name: app.name, classPath: dnsApp.classPath };
        }
        this.opts.log.warn("no query logger app found in Technitium; recent blocks will be empty");
        return null;
      })
      .catch((err: unknown) => {
        this.loggerApp = null; // retry next time
        throw err;
      });
    return this.loggerApp;
  }

  async recentBlocked(opts: { since: Date; clientIp?: string; limit?: number }): Promise<BlockedQuery[]> {
    const app = await this.getLoggerApp();
    if (!app) return [];
    const page = await this.client.queryLogs({
      ...app,
      start: opts.since,
      clientIpAddress: opts.clientIp,
      responseType: "Blocked",
      entriesPerPage: opts.limit ?? 500,
    });
    return page.entries.map((e) => ({
      timestamp: Date.parse(e.timestamp),
      clientIp: normalizeIp(e.clientIpAddress),
      domain: e.qname.toLowerCase().replace(/\.$/, ""),
      qtype: e.qtype,
    }));
  }

  private getResolver(): Promise<Resolver> {
    this.resolver ??= (async () => {
      let server = this.opts.dnsServer ?? new URL(this.opts.technitiumUrl).hostname;
      if (!isIP(server)) server = (await lookup(server)).address;
      const r = new Resolver({ timeout: 1500, tries: 1 });
      r.setServers([server]);
      return r;
    })();
    return this.resolver;
  }

  /** Reverse-DNS name for a client (cached); null if none. Never throws. */
  async clientName(ip: string): Promise<string | null> {
    const cached = this.names.get(ip);
    if (cached && Date.now() - cached.at < NAME_TTL_MS) return cached.name;
    let name: string | null = null;
    try {
      const [first] = await (await this.getResolver()).reverse(ip);
      name = first ?? null;
    } catch {
      name = null;
    }
    this.names.set(ip, { name, at: Date.now() });
    return name;
  }
}

/** Collapse raw blocked queries into one row per client + domain, newest first. */
export function summarize(queries: BlockedQuery[]): Omit<BlockedSummary, "clientName">[] {
  const map = new Map<string, Omit<BlockedSummary, "clientName">>();
  for (const q of queries) {
    const key = `${q.clientIp}|${q.domain}`;
    const row = map.get(key);
    if (row) {
      row.count++;
      row.lastSeen = Math.max(row.lastSeen, q.timestamp);
    } else map.set(key, { clientIp: q.clientIp, domain: q.domain, count: 1, lastSeen: q.timestamp });
  }
  return [...map.values()].sort((a, b) => b.lastSeen - a.lastSeen);
}

/** Domains the same client was blocked on around `at` (sibling CDN/API hosts a site needs). */
export function siblingDomains(queries: BlockedQuery[], clientIp: string, at: number, exclude: string, windowMs = 60_000) {
  const out = new Set<string>();
  for (const q of queries) {
    if (q.clientIp === clientIp && Math.abs(q.timestamp - at) <= windowMs && q.domain !== exclude) out.add(q.domain);
  }
  return [...out].sort();
}
