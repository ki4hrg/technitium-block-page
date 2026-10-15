import { describe, expect, it } from "vitest";
import { createHarness, form, HA_TOKEN, JANE, JOHN, KID_USER } from "./fixtures.js";

const json = async (r: Response | Promise<Response>): Promise<any> => (await r).json();
const codeFrom = (html: string) => /class="code">([A-Z0-9]{3}-[A-Z0-9]{3})</.exec(html)?.[1];

describe("block page", () => {
  it("records a block event and shows the approval code to kids", async () => {
    const h = createHarness();
    const res = await h.block("/watch?v=1");
    expect(res.status).toBe(403);
    const html = await res.text();
    expect(html).toContain("youtube.com");
    const code = codeFrom(html);
    expect(code).toBeTruthy();
    expect(html).toContain(`https://blocks.example.test/r/${code}?return=`);
    expect(html).toContain("Send request");
    expect(html).not.toContain('action="/_tbp/act"'); // kids can't self-serve
    expect(h.emitted.map((e) => e.type)).toEqual(["block.created"]);

    // Reloading keeps the same code.
    expect(codeFrom(await (await h.block("/watch?v=1")).text())).toBe(code);
  });

  it("does not render pages for non-HTML subresources", async () => {
    const h = createHarness();
    const res = await h.block("/x.js", { headers: { accept: "*/*" } });
    expect(res.status).toBe(403);
    expect(h.repo.recentEvents({ since: 0 })).toHaveLength(0);
  });

  it("lets trusted devices self-serve and syncs Technitium", async () => {
    const h = createHarness();
    h.setClientIp("10.0.10.20");
    const html = await (await h.block("/")).text();
    expect(html).toContain('action="/_tbp/act"');
    const code = /name="code" value="([A-Z0-9-]+)"/.exec(html)![1]!;

    const res = await h.block("/_tbp/act", form({ code, action: "allow", duration: "1h" }));
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("http://youtube.com/");
    await h.reconciler.run();
    expect(h.technitium.group("trusted").allowed).toEqual(["youtube.com"]);

    const status = await json(h.block(`/_tbp/status/${code}`));
    expect(status.state).toBe("allowed");
  });

  it("rejects self-service from kids and acting on another device's code", async () => {
    const h = createHarness();
    const code = codeFrom(await (await h.block("/")).text())!;
    const res = await h.block("/_tbp/act", form({ code, action: "allow", duration: "15m" }));
    expect(res.status).toBe(403);

    h.setClientIp("10.0.30.99");
    expect((await h.block("/_tbp/act", form({ code, action: "allow", duration: "15m" }))).status).toBe(404);
    expect((await h.block(`/_tbp/status/${code}`)).status).toBe(404);
  });

  it("shows the device home page on the block page's own hostname", async () => {
    const h = createHarness();
    h.technitium.logBlocked("10.0.30.5", "tiktok.com");
    h.technitium.logBlocked("10.0.30.6", "other-device.com");
    const html = await (await h.block("/", { host: "blocked.home.arpa" })).text();
    expect(html).toContain("tiktok.com");
    expect(html).not.toContain("other-device.com");
  });
});

describe("parent approval", () => {
  it("approves a kid's request from another device, including sibling domains", async () => {
    const h = createHarness();
    const now = Date.now();
    h.technitium.logBlocked("10.0.30.5", "youtube.com", now);
    h.technitium.logBlocked("10.0.30.5", "i.ytimg.com", now);
    h.technitium.logBlocked("10.0.30.5", "unrelated.com", now - 10 * 60_000);

    const code = codeFrom(await (await h.block("/")).text())!;
    await h.block("/_tbp/request", form({ code, note: "homework video" }));
    expect((await json(h.block(`/_tbp/status/${code}`))).state).toBe("requested");

    // Not signed in -> redirected to login.
    const anon = await h.admin(`/r/${code}`);
    expect(anon.status).toBe(302);
    expect(anon.headers.get("location")).toMatch(/^\/auth\/login\?return=/);

    // A user without permission for the Kids VLAN.
    expect((await h.admin(`/r/${code}`, { user: KID_USER })).status).toBe(403);

    const page = await (await h.admin(`/r/${code}`, { user: JANE })).text();
    expect(page).toContain("homework video");
    expect(page).toContain("i.ytimg.com");
    expect(page).not.toContain("unrelated.com");
    expect(page).not.toContain("Pause all blocking"); // only john may pause kids

    const res = await h.admin(`/r/${code}/allow`, { ...form({ duration: "1h", extra: ["i.ytimg.com"] }), user: JANE });
    expect(res.status).toBe(303);
    await h.reconciler.run();
    expect(h.technitium.group("kids").allowed).toEqual(["manual.example", "i.ytimg.com", "youtube.com"]);
    expect((await json(h.block(`/_tbp/status/${code}`))).state).toBe("allowed");
    expect(h.repo.listRequests({ status: "approved" })).toHaveLength(1);
    expect(h.emitted.map((e) => e.type)).toContain("request.approved");
  });

  it("rejects durations the policy doesn't offer and cross-origin posts", async () => {
    const h = createHarness();
    const code = codeFrom(await (await h.block("/")).text())!;
    const bad = await h.admin(`/r/${code}/allow`, { ...form({ duration: "7d" }), user: JANE });
    expect(bad.status).toBe(400);
    const csrf = await h.admin(`/r/${code}/allow`, {
      ...form({ duration: "1h" }),
      user: JANE,
      headers: { origin: "https://evil.test", "content-type": "application/x-www-form-urlencoded" },
    });
    expect(csrf.status).toBe(403);
  });

  it("only redirects back to the blocked site after approving on the same device", async () => {
    const h = createHarness();
    const code = codeFrom(await (await h.block("/")).text())!;
    const res = await h.admin(`/r/${code}/allow?return=${encodeURIComponent("https://evil.test/")}`, {
      ...form({ duration: "15m" }),
      user: JANE,
    });
    expect(res.headers.get("location")).toBe(`/r/${code}?done=1`);
    const ok = await h.admin(`/r/${code}/allow?return=${encodeURIComponent("http://youtube.com/watch")}`, {
      ...form({ duration: "15m" }),
      user: JANE,
    });
    expect(ok.headers.get("location")).toContain("return=");
  });

  it("pauses a VLAN, then resumes when revoked", async () => {
    const h = createHarness();
    const code = codeFrom(await (await h.block("/")).text())!;
    await h.admin(`/r/${code}/pause`, { ...form({ duration: "30m" }), user: JOHN });
    await h.reconciler.run();
    expect(h.technitium.group("kids").enableBlocking).toBe(false);

    const [pause] = h.repo.activeOverrides();
    await h.admin(`/overrides/${pause!.id}/revoke`, { ...form({}), user: JOHN });
    await h.reconciler.run();
    expect(h.technitium.group("kids").enableBlocking).toBe(true);
  });
});

describe("api v1 (integrations)", () => {
  const ha = (actor: string, init: RequestInit = {}) => ({
    ...init,
    headers: { authorization: `Bearer ${HA_TOKEN}`, "x-actor": actor, "content-type": "application/json" },
  });

  it("lets a mapped Home Assistant user approve within their groups", async () => {
    const h = createHarness();
    const code = codeFrom(await (await h.block("/")).text())!;
    await h.block("/_tbp/request", form({ code }));

    const list = await json(h.admin("/api/v1/requests", ha("grandma")));
    expect(list).toHaveLength(1);
    expect(list[0].code).toBe(code);

    const denied = await h.admin(
      `/api/v1/requests/${list[0].id}/approve`,
      ha("grandma", { method: "POST", body: JSON.stringify({ duration: "permanent" }) }),
    );
    expect(denied.status).toBe(403); // grandparents can't allow permanently

    const ok = await h.admin(
      `/api/v1/requests/${list[0].id}/approve`,
      ha("grandma", { method: "POST", body: JSON.stringify({ duration: "1h" }) }),
    );
    expect(ok.status).toBe(200);
    expect(h.repo.recentAudit()[0]!.actor).toBe("grandma via homeassistant");
  });

  it("rejects unknown actors, bad tokens, and unmapped HA users with Pocket ID names", async () => {
    const h = createHarness();
    expect((await h.admin("/api/v1/status", ha("stranger"))).status).toBe(403);
    expect(
      (await h.admin("/api/v1/status", { headers: { authorization: "Bearer nope", "x-actor": "grandma" } })).status,
    ).toBe(401);
    // HA "john" has no groups, so isn't treated as the Pocket ID admin "john".
    const res = await h.admin(
      "/api/v1/overrides",
      ha("john", { method: "POST", body: JSON.stringify({ scope: "kids", kind: "pause", duration: "30m" }) }),
    );
    expect(res.status).toBe(403);
  });

  it("reports status and supports global pause including built-in blocking", async () => {
    const h = createHarness();
    const res = await h.admin("/api/v1/overrides", {
      user: { ...JANE, groups: ["admins"] },
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ scope: "global", kind: "pause", duration: "1h" }),
    });
    expect(res.status).toBe(201);
    await h.reconciler.run();
    expect(h.technitium.appConfig.enableBlocking).toBe(false);
    expect(h.technitium.settings.enableBlocking).toBe(false);

    const status = await json(h.admin("/api/v1/status", { user: { ...JANE, groups: ["admins"] } }));
    expect(status.global.paused.kind).toBe("pause");

    const [o] = h.repo.activeOverrides();
    await h.admin(`/api/v1/overrides/${o!.id}`, { user: JOHN, method: "DELETE" });
    await h.reconciler.run();
    expect(h.technitium.appConfig.enableBlocking).toBe(true);
    expect(h.technitium.settings.enableBlocking).toBe(true);
  });
});

describe("reconciler", () => {
  it("only writes when something changed and removes expired overrides", async () => {
    const h = createHarness();
    await h.reconciler.run();
    expect(h.technitium.writes).toBe(0);

    const o = h.repo.createOverride({
      scope: "vlan",
      vlanId: "kids",
      kind: "allow",
      domain: "example.com",
      expiresAt: Date.now() + 50,
      createdBy: "test",
    });
    await h.reconciler.run();
    expect(h.technitium.writes).toBe(1);
    expect(h.technitium.group("kids").allowed).toContain("example.com");
    await h.reconciler.run();
    expect(h.technitium.writes).toBe(1);

    await new Promise((r) => setTimeout(r, 80));
    await h.reconciler.run();
    expect(h.technitium.group("kids").allowed).toEqual(["manual.example"]);
    expect(o.id).toBeGreaterThan(0);
    h.reconciler.stop();
  });

  it("surfaces Technitium errors in status and recovers", async () => {
    const h = createHarness();
    h.technitium.failing = true;
    await h.reconciler.run();
    expect(h.reconciler.status.lastError).toMatch(/HTTP 500/);
    expect((await h.admin("/healthz")).status).toBe(503);
    h.technitium.failing = false;
    await h.reconciler.run();
    expect(h.reconciler.status.lastError).toBeNull();
  });
});
