import { appendFileSync, chmodSync, statSync } from "node:fs";
import { join } from "node:path";
import { ensurePrivateDir } from "./fsutil.ts";
import type { Redactor } from "./secrets/redact.ts";

export type AuditEvent = "start" | "end" | "refused" | "plan" | "approval" | "server" | "note";

export interface AuditEntry {
  readonly event: AuditEvent;
  readonly profile?: string | undefined;
  readonly tool?: string | undefined;
  readonly class?: string | undefined;
  /** The redacted command line. Never a password. */
  readonly command?: string | undefined;
  readonly exitCode?: number | null | undefined;
  readonly durationMs?: number | undefined;
  readonly ok?: boolean | undefined;
  readonly timedOut?: boolean | undefined;
  readonly reason?: string | undefined;
  /** accept | decline | cancel | timeout | unsupported | mismatch | error | not-required */
  readonly decision?: string | undefined;
  /** Path of a secrets file. A path, never its content. */
  readonly secretsFile?: string | undefined;
  readonly note?: string | undefined;
}

const MAX_FIELD = 2000;

/**
 * What a refusal was about, in a small fixed set: the throttle below is per kind, so a flood of one kind (invalid
 * arguments, say) can never hide a refusal of another kind (a protected target, a forged token).
 */
export function reasonKind(reason: string | undefined): string {
  const r = (reason ?? "").toLowerCase();
  if (/^(invalid arguments|unknown tool|no such profile)/.test(r)) return "invalid";
  if (r.startsWith("passwords are never parameters")) return "password";
  if (/does not allow (write|destructive|admin) tools/.test(r)) return "class";
  if (/ is protected in |cannot be changed through this server/.test(r)) return "protected";
  if (r.includes("plantoken")) return "token";
  if (/rate limit|too many approval questions|already waiting/.test(r)) return "rate";
  if (/does not list the command|no ssh login|not enabled|no human approval/.test(r)) return "unavailable";
  if (r.startsWith("internal error")) return "internal";
  return "other";
}
/** Records a model can cause at will (refusals, dry runs, reads) are written at most this many per minute and kind; the rest are counted. */
export const THROTTLED_PER_MINUTE = 120;

/**
 * Append-only JSONL at <state>/audit.jsonl, mode 600. Every string passes through the redactor once
 * more and is bounded before it is written.
 */
export class AuditLog {
  readonly path: string;
  private readonly stateDir: string;
  private readonly redactor: Redactor;
  private readonly now: () => Date;
  private readonly windows = new Map<string, { minute: number; written: number; dropped: number }>();

  constructor(stateDir: string, redactor: Redactor, now: () => Date = () => new Date()) {
    this.stateDir = stateDir;
    this.redactor = redactor;
    this.now = now;
    this.path = join(stateDir, "audit.jsonl");
  }

  /** Throws when the line cannot be written: callers treat that as "do not run the command". */
  record(entry: AuditEntry): void {
    ensurePrivateDir(this.stateDir);
    const minute = this.minuteNow();
    this.flush(false, minute);
    const kind = this.kindOf(entry);
    if (kind !== null && !this.admit(kind, minute)) return;
    this.write(entry);
  }

  /**
   * Writes how many records each finished minute held back, whatever the next record is about (waiting for
   * another record of the same kind could mean never). With `all`, the running minute's count too: at shutdown.
   */
  flush(all: boolean = true, minute: number = this.minuteNow()): void {
    for (const [kind, window] of this.windows) {
      if (window.minute === minute && !all) continue;
      this.windows.delete(kind);
      if (window.dropped > 0) {
        const began = new Date(window.minute * 60_000).toISOString().slice(0, 16);
        this.write({ event: "note", note: `${window.dropped} "${kind}" records were not written in the minute that began ${began}Z (more than ${THROTTLED_PER_MINUTE} a minute)` });
      }
    }
  }

  private minuteNow(): number {
    return Math.floor(this.now().getTime() / 60_000);
  }

  /** The kind of a record a model can cause at will, or null for the records that are never held back. */
  private kindOf(entry: AuditEntry): string | null {
    const cls = entry.class ?? "";
    if (entry.event === "refused") return `refused:${cls}:${reasonKind(entry.reason)}`;
    if (entry.event === "plan") return `plan:${cls}`;
    if (entry.event === "approval" && entry.decision === "unsupported") return `approval:${cls}:unsupported`;
    if (cls === "read") return `${entry.event}:read`;
    return null;
  }

  /** True when a record of this throttled kind may be written now; counts the ones that may not. */
  private admit(kind: string, minute: number): boolean {
    let window = this.windows.get(kind);
    if (window === undefined) {
      // flush() has just closed every window of an earlier minute, so one that is still here is this minute's
      window = { minute, written: 0, dropped: 0 };
      this.windows.set(kind, window);
    }
    if (window.written >= THROTTLED_PER_MINUTE) {
      if (window.dropped === 0) this.write({ event: "note", note: `more than ${THROTTLED_PER_MINUTE} "${kind}" records this minute: the rest are counted, not written` });
      window.dropped += 1;
      return false;
    }
    window.written += 1;
    return true;
  }

  private write(entry: AuditEntry): void {
    const clean: Record<string, unknown> = { time: this.now().toISOString() };
    for (const [key, value] of Object.entries(entry)) {
      if (value === undefined) continue;
      clean[key] = typeof value === "string" ? this.redactor.scrub(value).slice(0, MAX_FIELD) : value;
    }
    appendFileSync(this.path, `${JSON.stringify(clean)}\n`, { flag: "a", mode: 0o600 });
    try {
      if ((statSync(this.path).mode & 0o777) !== 0o600) chmodSync(this.path, 0o600);
    } catch {
      // Windows
    }
  }
}
