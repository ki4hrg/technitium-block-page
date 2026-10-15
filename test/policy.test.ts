import { describe, expect, it } from "vitest";
import { cidrContains, normalizeIp, parseCidr } from "../src/lib/cidr.js";
import { resolveExpiry } from "../src/lib/duration.js";
import { normalizeCode, generateCode } from "../src/db/repo.js";
import { Policy, type Principal } from "../src/policy.js";
import { testPolicy } from "./fixtures.js";

describe("cidr", () => {
  it("matches IPv4 and IPv4-mapped IPv6", () => {
    const c = parseCidr("10.0.30.0/24");
    expect(cidrContains(c, "10.0.30.7")).toBe(true);
    expect(cidrContains(c, "::ffff:10.0.30.7")).toBe(true);
    expect(cidrContains(c, "10.0.31.7")).toBe(false);
    expect(normalizeIp("::ffff:192.168.1.1")).toBe("192.168.1.1");
  });

  it("matches IPv6 prefixes", () => {
    const c = parseCidr("fd00:30::/64");
    expect(cidrContains(c, "fd00:30::abcd")).toBe(true);
    expect(cidrContains(c, "fd00:31::1")).toBe(false);
    expect(cidrContains(c, "10.0.30.1")).toBe(false);
  });
});

describe("duration", () => {
  it("resolves relative, today and permanent", () => {
    expect(resolveExpiry("15m", 0)).toBe(900_000);
    expect(resolveExpiry("permanent")).toBeNull();
    const now = new Date(2026, 9, 15, 20, 30).getTime();
    expect(resolveExpiry("today", now)).toBe(new Date(2026, 9, 16).getTime());
  });
});

describe("codes", () => {
  it("generates readable codes and normalizes input", () => {
    const code = generateCode();
    expect(code).toMatch(/^[2-9A-Z]{3}-[2-9A-Z]{3}$/);
    expect(code).not.toMatch(/[01OIL]/);
    expect(normalizeCode("k7f 2qd")).toBe("K7F-2QD");
    expect(normalizeCode("abc")).toBeNull();
  });
});

describe("policy", () => {
  const policy = new Policy(testPolicy());
  const kidDevice: Principal = { kind: "network", ip: "10.0.30.5", vlanId: "kids" };
  const trustedDevice: Principal = { kind: "network", ip: "10.0.10.5", vlanId: "trusted" };
  const parent: Principal = { kind: "user", id: "p1", username: "jane", name: "Jane", groups: ["parents"], via: "oidc" };
  const john: Principal = { kind: "user", id: "j1", username: "john", name: "John", groups: [], via: "oidc" };
  const grandma: Principal = {
    kind: "user",
    id: "homeassistant:grandma",
    username: "grandma",
    name: "grandma",
    groups: ["grandparents"],
    via: "homeassistant",
  };
  const haJohn: Principal = { ...grandma, id: "homeassistant:john", username: "john", groups: [] };

  it("maps IPs to VLANs by longest prefix", () => {
    expect(policy.vlanForIp("10.0.30.9")?.id).toBe("kids");
    expect(policy.vlanForIp("10.0.10.9")?.id).toBe("trusted");
    expect(policy.vlanForIp("10.0.99.9")).toBeUndefined();
  });

  it("lets trusted devices self-serve but not kids", () => {
    const trusted = { kind: "vlan", vlanId: "trusted" } as const;
    const kids = { kind: "vlan", vlanId: "kids" } as const;
    expect(policy.can(trustedDevice, trusted, "allowTemporary")).toBe(true);
    expect(policy.can(trustedDevice, kids, "allowTemporary")).toBe(false);
    expect(policy.can(kidDevice, kids, "allowTemporary")).toBe(false);
    expect(policy.canRequest(kidDevice, "kids")).toBe(true);
    expect(policy.canRequest(trustedDevice, "kids")).toBe(false);
  });

  it("checks groups and users", () => {
    const kids = { kind: "vlan", vlanId: "kids" } as const;
    expect(policy.can(parent, kids, "allowTemporary")).toBe(true);
    expect(policy.can(parent, kids, "pause")).toBe(false);
    expect(policy.can(john, kids, "pause")).toBe(true);
    expect(policy.can(grandma, kids, "allowTemporary")).toBe(true);
    expect(policy.can(grandma, kids, "allowPermanent")).toBe(false);
  });

  it("never matches integration actors by user name", () => {
    expect(policy.can(haJohn, { kind: "vlan", vlanId: "kids" }, "pause")).toBe(false);
    expect(policy.isAdmin(haJohn)).toBe(false);
    expect(policy.isAdmin(john)).toBe(true);
  });
});

describe("example policy", () => {
  it("parses", async () => {
    const { readFileSync } = await import("node:fs");
    const { parse } = await import("yaml");
    const { parsePolicy } = await import("../src/config.js");
    const p = parsePolicy(parse(readFileSync("config/policy.example.yaml", "utf8")));
    expect(p.vlans.map((v) => v.id)).toEqual(["trusted", "kids"]);
  });
});
