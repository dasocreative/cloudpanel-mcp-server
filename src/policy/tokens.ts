import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** JSON with sorted keys, so equal arguments always give the same string. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export type TokenCheck =
  | { readonly ok: true; readonly nonce: string }
  | { readonly ok: false; readonly reason: string };

export const TOKEN_TTL_MS = 10 * 60_000;
/** Consumed nonces are kept (oldest dropped first) rather than expired by the clock: a clock stepped back must not revive a used token. */
export const MAX_CONSUMED = 10_000;

/**
 * Plan tokens: an HMAC over tool, profile and the canonical arguments, with an expiry and a nonce
 * that can be used once. The key is random per process, so a restart invalidates every token.
 * The token proves that THIS call was planned; it is not a secret and not an approval.
 */
export class PlanTokens {
  private readonly key: Buffer;
  private readonly now: () => number;
  private readonly ttlMs: number;
  private readonly consumed = new Map<string, number>();

  constructor(options: { key?: Buffer; now?: () => number; ttlMs?: number } = {}) {
    this.key = options.key ?? randomBytes(32);
    this.now = options.now ?? Date.now;
    this.ttlMs = options.ttlMs ?? TOKEN_TTL_MS;
  }

  private mac(purpose: string, nonce: string, expiry: string, binding: string): Buffer {
    return createHmac("sha256", this.key)
      .update(`${purpose}\n${nonce}\n${expiry}\n${binding}`)
      .digest();
  }

  /** A short, stable key derived from the binding (used to name the approval request). */
  derive(purpose: string, binding: string): string {
    return this.mac(purpose, "-", "-", binding).toString("hex").slice(0, 16);
  }

  /** When (epoch milliseconds) a token in this form lapses, or undefined. It says nothing about whether the token is genuine. */
  expiryOf(token: string): number | undefined {
    const parts = token.split(".");
    const expiry = parts[2];
    return parts.length === 4 && expiry !== undefined && /^[0-9]{10,16}$/.test(expiry) ? Number(expiry) : undefined;
  }

  issue(binding: string): { token: string; expiresInSeconds: number } {
    const nonce = randomBytes(12).toString("hex");
    const expiry = String(this.now() + this.ttlMs);
    const mac = this.mac("plan-v1", nonce, expiry, binding).toString("base64url");
    return { token: `v1.${nonce}.${expiry}.${mac}`, expiresInSeconds: Math.round(this.ttlMs / 1000) };
  }

  verify(token: string, binding: string): TokenCheck {
    const parts = token.split(".");
    const [version, nonce, expiry, mac] = parts;
    if (parts.length !== 4 || version !== "v1" || !nonce || !expiry || !mac) {
      return { ok: false, reason: "the planToken is malformed" };
    }
    if (!/^[0-9a-f]{24}$/.test(nonce) || !/^[0-9]{10,16}$/.test(expiry)) {
      return { ok: false, reason: "the planToken is malformed" };
    }
    const expected = this.mac("plan-v1", nonce, expiry, binding);
    let given: Buffer;
    try {
      given = Buffer.from(mac, "base64url");
    } catch {
      return { ok: false, reason: "the planToken is malformed" };
    }
    // only the one canonical spelling: base64url decoding ignores the unused low bits of the last character, so
    // "...B" and "...A" can decode to the same bytes; a token must be exactly the string that was issued
    if (given.toString("base64url") !== mac) {
      return { ok: false, reason: "the planToken is malformed" };
    }
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      return { ok: false, reason: "the planToken does not belong to this tool, profile and these arguments (or to this server process): run a dry run again" };
    }
    if (Number(expiry) < this.now()) {
      return { ok: false, reason: "the planToken has expired: run a dry run again" };
    }
    if (this.consumed.has(nonce)) {
      return { ok: false, reason: "the planToken was already used: run a dry run again" };
    }
    return { ok: true, nonce };
  }

  /** Marks a nonce as used. Returns false if it already was (a concurrent second use). */
  consume(nonce: string): boolean {
    if (this.consumed.has(nonce)) return false;
    this.consumed.set(nonce, this.now() + this.ttlMs);
    while (this.consumed.size > MAX_CONSUMED) {
      const oldest = this.consumed.keys().next().value;
      if (oldest === undefined) break;
      this.consumed.delete(oldest);
    }
    return true;
  }
}
