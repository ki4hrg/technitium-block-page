// Minimal typed client for the Technitium DNS Server HTTP API (v15+).
// Docs: https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md

export class TechnitiumError extends Error {
  constructor(
    message: string,
    readonly status?: string,
  ) {
    super(message);
  }
}

export interface QueryLogEntry {
  rowNumber: number;
  timestamp: string;
  clientIpAddress: string;
  protocol: string;
  responseType: string;
  rcode: string;
  qname: string;
  qtype: string;
  qclass: string;
  answer: string;
}

export interface QueryLogPage {
  pageNumber: number;
  totalPages: number;
  totalEntries: number;
  entries: QueryLogEntry[];
}

export interface QueryLogParams {
  name: string;
  classPath: string;
  pageNumber?: number;
  entriesPerPage?: number;
  descendingOrder?: boolean;
  start?: Date;
  end?: Date;
  clientIpAddress?: string;
  responseType?: "Blocked" | "UpstreamBlocked" | "UpstreamBlockedCached";
  qname?: string;
}

export interface InstalledApp {
  name: string;
  version: string;
  dnsApps: { classPath: string; description?: string; isQueryLogger?: boolean }[];
}

export interface BlockingSettings {
  enableBlocking: boolean;
  temporaryDisableBlockingTill?: string;
  blockingType?: string;
  customBlockingAddresses?: string[];
  blockListUrls?: string[];
  blockingAnswerTtl?: number;
}

type Fetch = typeof fetch;

export class TechnitiumClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  private async call<T>(
    path: string,
    params: Record<string, string | number | boolean | undefined> = {},
    body?: Record<string, string>,
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, String(v));
    const res = await this.fetchImpl(url, {
      method: body ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
      },
      body: body ? new URLSearchParams(body).toString() : undefined,
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new TechnitiumError(`Technitium ${path} returned HTTP ${res.status}`);
    const json = (await res.json()) as { status: string; response?: T; errorMessage?: string };
    if (json.status !== "ok") {
      throw new TechnitiumError(`Technitium ${path}: ${json.errorMessage ?? json.status}`, json.status);
    }
    return json.response as T;
  }

  async getAppConfig(appName: string): Promise<string | null> {
    const r = await this.call<{ config: string | null }>("/api/apps/config/get", { name: appName });
    return r.config;
  }

  async setAppConfig(appName: string, config: string): Promise<void> {
    await this.call("/api/apps/config/set", { name: appName }, { config });
  }

  async listApps(): Promise<InstalledApp[]> {
    const r = await this.call<{ apps: InstalledApp[] }>("/api/apps/list");
    return r.apps;
  }

  async queryLogs(p: QueryLogParams): Promise<QueryLogPage> {
    return this.call<QueryLogPage>("/api/logs/query", {
      name: p.name,
      classPath: p.classPath,
      pageNumber: p.pageNumber ?? 1,
      entriesPerPage: p.entriesPerPage ?? 100,
      descendingOrder: p.descendingOrder ?? true,
      start: p.start ? technitiumDate(p.start) : undefined,
      end: p.end ? technitiumDate(p.end) : undefined,
      clientIpAddress: p.clientIpAddress,
      responseType: p.responseType,
      qname: p.qname,
    });
  }

  async getSettings(): Promise<BlockingSettings> {
    return this.call<BlockingSettings>("/api/settings/get");
  }

  async setBuiltInBlocking(enabled: boolean): Promise<void> {
    await this.call("/api/settings/set", { enableBlocking: enabled });
  }

  async temporaryDisableBlocking(minutes: number): Promise<string> {
    const r = await this.call<{ temporaryDisableBlockingTill: string }>("/api/settings/temporaryDisableBlocking", {
      minutes,
    });
    return r.temporaryDisableBlockingTill;
  }
}

/** Technitium parses start/end with invariant culture as UTC; ISO without the "Z" is safest. */
function technitiumDate(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "");
}
