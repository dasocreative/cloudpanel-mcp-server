import type { RateLimit } from "../config/types.ts";

export type RateDecision =
  | { readonly ok: true }
  | { readonly ok: false; readonly retryAfterSeconds: number };

/** Sliding-window limiter: at most `max` hits per `perMinutes`, per key. In memory, per process. */
export class RateLimiter {
  private readonly hits = new Map<string, number[]>();
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  /** Checks the limit without recording anything. */
  check(key: string, limit: RateLimit): RateDecision {
    const now = this.now();
    const windowMs = limit.perMinutes * 60_000;
    const recent = (this.hits.get(key) ?? []).filter((t) => now - t < windowMs);
    this.hits.set(key, recent);
    if (recent.length >= limit.max) {
      const oldest = recent[0] ?? now;
      return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000)) };
    }
    return { ok: true };
  }

  /** Checks the limit and, when it allows, records the hit. */
  take(key: string, limit: RateLimit): RateDecision {
    const decision = this.check(key, limit);
    if (decision.ok) {
      const recent = this.hits.get(key) ?? [];
      recent.push(this.now());
      this.hits.set(key, recent);
    }
    return decision;
  }
}
