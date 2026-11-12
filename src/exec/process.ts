import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";

export const MAX_CAPTURE_BYTES = 1024 * 1024;
const EXIT_GRACE_MS = 1_500;
const KILL_GRACE_MS = 2_000;

export interface RunResult {
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
  /** Everything captured (bounded), not yet scrubbed or truncated. */
  readonly stdout: string;
  readonly stderr: string;
  readonly droppedBytes: number;
  readonly durationMs: number;
  readonly spawnError?: string;
}

class Capture {
  dropped = 0;
  private readonly chunks: Buffer[] = [];
  private size = 0;

  push(chunk: Buffer): void {
    const room = MAX_CAPTURE_BYTES - this.size;
    if (room <= 0) {
      this.dropped += chunk.length;
      return;
    }
    if (chunk.length > room) {
      this.chunks.push(chunk.subarray(0, room));
      this.size = MAX_CAPTURE_BYTES;
      this.dropped += chunk.length - room;
      return;
    }
    this.chunks.push(chunk);
    this.size += chunk.length;
  }

  text(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }
}

type Child = ChildProcessByStdio<null, Readable, Readable>;
const active = new Set<Child>();

/** Kills every child that is still running (server shutdown). */
export function killActive(): void {
  for (const child of active) child.kill("SIGKILL");
}

export interface ProcessOptions {
  readonly timeoutMs: number;
  readonly env?: NodeJS.ProcessEnv;
}

/**
 * Runs a program through spawn, never through a local shell. stdin is /dev/null (it must never read
 * the MCP stdio stream). On timeout the child is killed.
 */
export function runProcess(
  file: string,
  args: readonly string[],
  options: ProcessOptions,
): Promise<RunResult> {
  return new Promise<RunResult>((resolve) => {
    const started = Date.now();
    const out = new Capture();
    const err = new Capture();
    let child: Child;
    try {
      child = spawn(file, [...args], {
        stdio: ["ignore", "pipe", "pipe"],
        shell: false,
        windowsHide: true,
        ...(options.env === undefined ? {} : { env: options.env }),
      });
    } catch (error) {
      resolve({
        exitCode: null,
        signal: null,
        timedOut: false,
        stdout: "",
        stderr: "",
        droppedBytes: 0,
        durationMs: Date.now() - started,
        spawnError: error instanceof Error ? error.message : "spawn failed",
      });
      return;
    }
    active.add(child);

    let timedOut = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;
    let graceTimer: NodeJS.Timeout | undefined;

    const finish = (
      exitCode: number | null,
      signal: string | null,
      spawnError?: string,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
      clearTimeout(graceTimer);
      active.delete(child);
      resolve({
        exitCode,
        signal,
        timedOut,
        stdout: out.text(),
        stderr: err.text(),
        droppedBytes: out.dropped + err.dropped,
        durationMs: Date.now() - started,
        ...(spawnError === undefined ? {} : { spawnError }),
      });
    };

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => child.kill("SIGKILL"), KILL_GRACE_MS);
      killTimer.unref();
    }, options.timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", (error) => finish(null, null, error.message));
    // A multiplexing master that stays in the background can hold the pipes open for
    // ControlPersist seconds. Do not wait for it: finish shortly after the client exits.
    child.on("exit", (code, signal) => {
      graceTimer = setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
        finish(code, signal);
      }, EXIT_GRACE_MS);
    });
    child.on("close", (code, signal) => finish(code, signal));
  });
}
