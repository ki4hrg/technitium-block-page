import * as oidc from "openid-client";
import type { Logger } from "../lib/log.js";
import type { SessionUser } from "./session.js";

/** Pocket ID (or any OIDC provider) login via authorization code + PKCE. */
export class OidcClient {
  private config: Promise<oidc.Configuration> | null = null;

  constructor(
    private readonly opts: {
      issuer: string;
      clientId: string;
      clientSecret: string;
      redirectUri: string;
      scopes: string;
      log: Logger;
    },
  ) {}

  private getConfig(): Promise<oidc.Configuration> {
    this.config ??= oidc
      .discovery(new URL(this.opts.issuer), this.opts.clientId, this.opts.clientSecret)
      .catch((err: unknown) => {
        this.config = null; // retry discovery on the next login
        this.opts.log.error("OIDC discovery failed", { error: String(err) });
        throw err;
      });
    return this.config;
  }

  async startLogin(): Promise<{ url: string; state: string; verifier: string }> {
    const config = await this.getConfig();
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: this.opts.redirectUri,
      scope: this.opts.scopes,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: "S256",
      state,
    });
    return { url: url.href, state, verifier };
  }

  /** `callbackUrl` must be the external URL the provider redirected to (incl. query string). */
  async finishLogin(callbackUrl: URL, state: string, verifier: string): Promise<SessionUser> {
    const config = await this.getConfig();
    const tokens = await oidc.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: verifier,
      expectedState: state,
    });
    const claims = tokens.claims();
    if (!claims) throw new Error("No ID token returned");
    let groups = claims.groups;
    let username = claims.preferred_username;
    let name = claims.name;
    if (!Array.isArray(groups) || !username) {
      // Fall back to userinfo if the ID token was trimmed.
      const info = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
      groups ??= info.groups;
      username ??= info.preferred_username;
      name ??= info.name;
    }
    return {
      sub: claims.sub,
      username: String(username ?? claims.email ?? claims.sub),
      name: String(name ?? username ?? claims.sub),
      groups: Array.isArray(groups) ? groups.map(String) : [],
    };
  }
}
