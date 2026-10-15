import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { timingSafeEqual } from "node:crypto";
import type { SessionUser } from "../../auth/session.js";
import type { Principal } from "../../policy.js";
import type { Deps } from "../context.js";

export const SESSION_COOKIE = "tbp_session";
const LOGIN_COOKIE = "tbp_login";
const SESSION_TTL_MS = 12 * 3_600_000;

export type AdminEnv = { Variables: { principal: Principal | null; viaToken: boolean } };

function secureCookies(publicUrl: string) {
  return publicUrl.startsWith("https://");
}

/** Only allow redirects back into the admin UI after login. */
export function safeReturnPath(p: string | undefined): string {
  return p && p.startsWith("/") && !p.startsWith("//") ? p : "/";
}

function lookupToken(tokens: Map<string, string>, presented: string): string | undefined {
  const a = Buffer.from(presented);
  for (const [token, id] of tokens) {
    const b = Buffer.from(token);
    if (a.length === b.length && timingSafeEqual(a, b)) return id;
  }
  return undefined;
}

/**
 * Resolves the acting principal from either:
 *  - an integration bearer token + `X-Actor` header (e.g. Home Assistant acting for a user), or
 *  - the sealed session cookie set after Pocket ID login.
 */
export function principalMiddleware(deps: Deps): MiddlewareHandler<AdminEnv> {
  return async (c, next) => {
    c.set("principal", null);
    c.set("viaToken", false);
    const auth = c.req.header("authorization");
    if (auth?.startsWith("Bearer ")) {
      const integrationId = lookupToken(deps.config.secrets.integrationTokens, auth.slice(7).trim());
      if (!integrationId) return c.json({ error: "invalid token" }, 401);
      const actor = c.req.header("x-actor")?.trim();
      if (!actor) return c.json({ error: "X-Actor header required" }, 400);
      const mapped = deps.config.policy.integrations[integrationId]?.users[actor];
      if (!mapped) return c.json({ error: `actor "${actor}" is not mapped for ${integrationId}` }, 403);
      c.set("viaToken", true);
      c.set("principal", {
        kind: "user",
        id: `${integrationId}:${actor}`,
        username: actor,
        name: actor,
        groups: mapped.groups,
        via: integrationId,
      });
      return next();
    }
    const session = deps.sealer.unseal<SessionUser>(getCookie(c, SESSION_COOKIE));
    if (session) {
      c.set("principal", {
        kind: "user",
        id: session.sub,
        username: session.username,
        name: session.name,
        groups: session.groups,
        via: "oidc",
      });
    }
    return next();
  };
}

/** Cookie-authenticated mutations must come from our own origin (SameSite=Lax is the first line). */
export function csrfGuard(publicUrl: string): MiddlewareHandler<AdminEnv> {
  const origin = new URL(publicUrl).origin;
  return async (c, next) => {
    if (c.req.method === "GET" || c.req.method === "HEAD" || c.get("viaToken")) return next();
    const presented = c.req.header("origin") ?? (c.req.header("referer") ? new URL(c.req.header("referer")!).origin : null);
    if (presented !== origin) return c.text("Cross-origin request rejected", 403);
    return next();
  };
}

export function requireUserPage(): MiddlewareHandler<AdminEnv> {
  return async (c, next) => {
    if (c.get("principal")) return next();
    const ret = c.req.method === "GET" ? c.req.path + (new URL(c.req.url).search || "") : "/";
    return c.redirect(`/auth/login?return=${encodeURIComponent(ret)}`);
  };
}

export function mountAuthRoutes(app: import("hono").Hono<AdminEnv>, deps: Deps) {
  const publicUrl = deps.config.policy.admin.publicUrl.replace(/\/$/, "");
  const secure = secureCookies(publicUrl);

  app.get("/auth/login", async (c) => {
    const { url, state, verifier } = await deps.oidc.startLogin();
    setCookie(c, LOGIN_COOKIE, deps.sealer.seal({ state, verifier, ret: safeReturnPath(c.req.query("return")) }, 600_000), {
      httpOnly: true,
      secure,
      sameSite: "Lax",
      path: "/auth",
      maxAge: 600,
    });
    return c.redirect(url);
  });

  app.get("/auth/callback", async (c) => {
    const login = deps.sealer.unseal<{ state: string; verifier: string; ret: string }>(getCookie(c, LOGIN_COOKIE));
    deleteCookie(c, LOGIN_COOKIE, { path: "/auth" });
    if (!login) return c.redirect("/auth/login");
    // The provider redirected to the *external* URL; rebuild it from publicUrl, not the proxied request.
    const callbackUrl = new URL(`${publicUrl}/auth/callback${new URL(c.req.url).search}`);
    let user: SessionUser;
    try {
      user = await deps.oidc.finishLogin(callbackUrl, login.state, login.verifier);
    } catch (err) {
      deps.log.warn("login failed", { error: String(err) });
      return c.text("Sign-in failed. Please try again.", 400);
    }
    setCookie(c, SESSION_COOKIE, deps.sealer.seal(user, SESSION_TTL_MS), {
      httpOnly: true,
      secure,
      sameSite: "Lax",
      path: "/",
      maxAge: SESSION_TTL_MS / 1000,
    });
    deps.log.info("login", { user: user.username, groups: user.groups });
    return c.redirect(login.ret);
  });

  app.post("/auth/logout", (c) => {
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
    return c.redirect("/signed-out");
  });

  app.get("/signed-out", (c) => c.text("Signed out."));
}

export function currentUser(c: Context<AdminEnv>) {
  const p = c.get("principal");
  return p?.kind === "user" ? p : null;
}
