import { describe, expect, it } from "vitest";
import {
  emptyDesired,
  groupFlag,
  render,
  TOP_FLAG,
  type AdvancedBlockingConfig,
  type ManagedState,
} from "../src/technitium/advancedBlocking.js";

const base = (): AdvancedBlockingConfig => ({
  enableBlocking: true,
  blockingAnswerTtl: 10,
  networkGroupMap: { "10.0.30.0/24": "kids", "0.0.0.0/0": "trusted" },
  groups: [
    { name: "kids", enableBlocking: true, allowed: ["manual.example"], blockListUrls: ["https://lists/kids.txt"] },
    { name: "trusted", enableBlocking: true, allowed: [], someFutureField: { x: 1 } },
  ],
});
const noManaged = (): ManagedState => ({ allowed: new Map(), flags: new Map() });

describe("render", () => {
  it("is a no-op with nothing desired", () => {
    const r = render(base(), emptyDesired(), noManaged());
    expect(r.changed).toBe(false);
    expect(r.config).toEqual(base());
  });

  it("adds allowed domains and records them as managed, preserving manual entries and unknown fields", () => {
    const d = emptyDesired();
    d.allowed.set("kids", new Set(["youtube.com", "ytimg.com"]));
    const r = render(base(), d, noManaged());
    expect(r.changed).toBe(true);
    const kids = r.config.groups!.find((g) => g.name === "kids")!;
    expect(kids.allowed).toEqual(["manual.example", "youtube.com", "ytimg.com"]);
    expect([...r.managed.allowed.get("kids")!]).toEqual(["youtube.com", "ytimg.com"]);
    expect(r.config.groups![1]!.someFutureField).toEqual({ x: 1 });
  });

  it("removes only our entries once overrides expire", () => {
    const d = emptyDesired();
    d.allowed.set("kids", new Set(["youtube.com"]));
    const first = render(base(), d, noManaged());
    const second = render(first.config, emptyDesired(), first.managed);
    expect(second.config.groups![0]!.allowed).toEqual(["manual.example"]);
    expect(second.managed.allowed.size).toBe(0);
  });

  it("does not take ownership of a domain that was already allowed manually", () => {
    const d = emptyDesired();
    d.allowed.set("kids", new Set(["manual.example"]));
    const first = render(base(), d, noManaged());
    expect(first.changed).toBe(false);
    expect(first.managed.allowed.get("kids")).toBeUndefined();
    const second = render(first.config, emptyDesired(), first.managed);
    expect(second.config.groups![0]!.allowed).toEqual(["manual.example"]);
  });

  it("applies global allows to every group", () => {
    const d = emptyDesired();
    d.allowedEverywhere.add("Example.COM.");
    const r = render(base(), d, noManaged());
    for (const g of r.config.groups!) expect(g.allowed).toContain("example.com");
  });

  it("pauses a group and restores its original value afterwards", () => {
    const cfg = base();
    cfg.groups![0]!.enableBlocking = true;
    const d = emptyDesired();
    d.pausedGroups.add("kids");
    const paused = render(cfg, d, noManaged());
    expect(paused.config.groups![0]!.enableBlocking).toBe(false);
    expect(paused.managed.flags.get(groupFlag("kids"))).toBe("true");

    // A second pass while still paused keeps the *original* value, not the paused one.
    const still = render(paused.config, d, paused.managed);
    expect(still.changed).toBe(false);
    expect(still.managed.flags.get(groupFlag("kids"))).toBe("true");

    const resumed = render(still.config, emptyDesired(), still.managed);
    expect(resumed.config.groups![0]!.enableBlocking).toBe(true);
    expect(resumed.managed.flags.size).toBe(0);
  });

  it("restores a group that was disabled before the pause as disabled", () => {
    const cfg = base();
    cfg.groups![1]!.enableBlocking = false;
    const d = emptyDesired();
    d.pausedGroups.add("trusted");
    const paused = render(cfg, d, noManaged());
    const resumed = render(paused.config, emptyDesired(), paused.managed);
    expect(resumed.config.groups![1]!.enableBlocking).toBe(false);
  });

  it("handles a global pause via the top-level flag", () => {
    const d = emptyDesired();
    d.globalPause = true;
    const paused = render(base(), d, noManaged());
    expect(paused.config.enableBlocking).toBe(false);
    expect(paused.managed.flags.get(TOP_FLAG)).toBe("true");
    const resumed = render(paused.config, emptyDesired(), paused.managed);
    expect(resumed.config.enableBlocking).toBe(true);
  });

  it("warns about groups that don't exist", () => {
    const d = emptyDesired();
    d.allowed.set("guests", new Set(["x.com"]));
    const r = render(base(), d, noManaged());
    expect(r.warnings[0]).toMatch(/guests/);
  });
});
