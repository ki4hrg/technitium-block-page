import type { PolicyConfig, Requirement, Vlan } from "./config.js";
import { cidrContains, parseCidr, type Cidr } from "./lib/cidr.js";

export type ActionName = "allowTemporary" | "allowPermanent" | "pause";
export type Scope = { kind: "vlan"; vlanId: string } | { kind: "global" };

/**
 * Who is acting:
 * - network: an unauthenticated device on the block page, identified only by source IP.
 * - user: a Pocket ID user (via "oidc") or a user an integration acts on behalf of (via "<integration id>").
 */
export type Principal =
  | { kind: "network"; ip: string; vlanId: string | null }
  | { kind: "user"; id: string; username: string; name: string; groups: string[]; via: string };

export function principalLabel(p: Principal): string {
  if (p.kind === "network") return `device ${p.ip}`;
  return p.via === "oidc" ? p.username : `${p.username} via ${p.via}`;
}

export class Policy {
  private readonly vlanCidrs: { vlan: Vlan; cidr: Cidr }[];

  constructor(readonly config: PolicyConfig) {
    this.vlanCidrs = config.vlans
      .flatMap((vlan) => vlan.cidrs.map((c) => ({ vlan, cidr: parseCidr(c) })))
      // Longest prefix wins, matching Advanced Blocking's networkGroupMap semantics.
      .sort((a, b) => b.cidr.prefix - a.cidr.prefix);
  }

  get vlans(): Vlan[] {
    return this.config.vlans;
  }

  vlan(id: string): Vlan | undefined {
    return this.config.vlans.find((v) => v.id === id);
  }

  vlanForIp(ip: string): Vlan | undefined {
    return this.vlanCidrs.find(({ cidr }) => cidrContains(cidr, ip))?.vlan;
  }

  isAdmin(p: Principal): boolean {
    if (p.kind !== "user") return false;
    const { users, groups } = this.config.admins;
    return matchesUser(p, users) || p.groups.some((g) => groups.includes(g));
  }

  actionConfig(scope: Scope, action: ActionName) {
    if (scope.kind === "global") return this.config.global[action];
    return this.vlan(scope.vlanId)?.actions[action];
  }

  /** Durations offered for an action, or [] if the action isn't available in this scope. */
  durations(scope: Scope, action: ActionName): string[] {
    if (action === "allowPermanent") return this.actionConfig(scope, action) ? ["permanent"] : [];
    const cfg = this.actionConfig(scope, action) as { durations: string[] } | undefined;
    return cfg?.durations ?? [];
  }

  can(p: Principal, scope: Scope, action: ActionName): boolean {
    const cfg = this.actionConfig(scope, action);
    if (!cfg) return false;
    if (this.isAdmin(p)) return true;
    return satisfies(p, cfg.require, scope);
  }

  /** Whether the principal can request (but not grant) an unblock for this VLAN. */
  canRequest(p: Principal, vlanId: string): boolean {
    const vlan = this.vlan(vlanId);
    if (!vlan?.actions.requestUnblock?.enabled) return false;
    return p.kind === "network" && p.vlanId === vlanId;
  }

  /** Can this principal act on anything in the scope (used to decide what the dashboard shows)? */
  canManage(p: Principal, scope: Scope): boolean {
    return (["allowTemporary", "allowPermanent", "pause"] as const).some((a) => this.can(p, scope, a));
  }
}

export function satisfies(p: Principal, req: Requirement, scope: Scope): boolean {
  if (req === "none") {
    if (p.kind === "user") return true;
    // An anonymous device may only act on its own VLAN (or globally if global policy is "none").
    return scope.kind === "global" || p.vlanId === scope.vlanId;
  }
  if (p.kind !== "user") return false;
  if (matchesUser(p, req.users)) return true;
  return p.groups.some((g) => req.groups.includes(g));
}

/**
 * `users` entries name Pocket ID users. Integration actors (e.g. a Home Assistant user) only gain
 * permissions through the groups their integration maps them to, so an HA user named "john"
 * is never mistaken for the Pocket ID user "john".
 */
function matchesUser(p: Extract<Principal, { kind: "user" }>, users: string[]): boolean {
  if (p.via !== "oidc") return false;
  return users.includes(p.username) || users.includes(p.id);
}
