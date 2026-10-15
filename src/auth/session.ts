import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

// Stateless sessions: AES-256-GCM sealed JSON in a cookie. Key derived from SESSION_SECRET.

export class Sealer {
  private readonly key: Buffer;

  constructor(secret: string) {
    this.key = createHash("sha256").update(`technitium-block-page:${secret}`).digest();
  }

  seal(payload: unknown, ttlMs: number): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const body = JSON.stringify({ p: payload, exp: Date.now() + ttlMs });
    const enc = Buffer.concat([cipher.update(body, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64url");
  }

  unseal<T>(token: string | undefined): T | null {
    if (!token) return null;
    try {
      const raw = Buffer.from(token, "base64url");
      const decipher = createDecipheriv("aes-256-gcm", this.key, raw.subarray(0, 12));
      decipher.setAuthTag(raw.subarray(12, 28));
      const body = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
      const { p, exp } = JSON.parse(body) as { p: T; exp: number };
      return exp > Date.now() ? p : null;
    } catch {
      return null;
    }
  }
}

export interface SessionUser {
  sub: string;
  username: string;
  name: string;
  groups: string[];
}
