import { createHash } from "node:crypto";
import { statSync } from "node:fs";
import { dirname, posix } from "node:path";
import { ensurePrivateDir } from "../fsutil.ts";
import type { Profile, SshTarget } from "../config/types.ts";
import { runProcess, type RunResult } from "./process.ts";
import { renderRemoteCommand } from "./quote.ts";

export interface RunRequest {
  /** The complete command: optional prefix ("sudo", "-n"), the clpctl path, the command, the tokens. */
  readonly argv: readonly string[];
  /** How many leading argv words are fixed (prefix, path, command) and need no quoting for ssh. */
  readonly fixedWords: number;
  readonly timeoutMs: number;
}

export interface Transport {
  run(request: RunRequest): Promise<RunResult>;
  /** For messages only: "ssh my-server" or "local". */
  readonly label: string;
}

export const DEFAULT_TIMEOUT_MS = 120_000;

/** Unix sockets are limited to 104 bytes on macOS; "%C" expands to 40 characters, ssh adds ~17. */
export function controlPathFits(dir: string): boolean {
  return Buffer.byteLength(dir) + "/cm-".length + 40 + 17 < 104;
}

export interface SshArgsOptions {
  readonly stateDir: string;
  readonly platform: NodeJS.Platform;
  /** false: no connection sharing (the socket directory could not be prepared). Default true. */
  readonly multiplex?: boolean;
  /** Changes when the identity file is replaced (size, modification time, inode), so a swapped key gets a new connection. */
  readonly identityStamp?: string;
}

/** How long a shared connection outlives its last use. A key removed on the server stops working this long after the last call. */
export const CONTROL_PERSIST_SECONDS = 15;

/**
 * A short name for everything that decides WHICH login a connection is. ssh shares a master connection
 * by local host, remote host, port and user ("%C"), not by key or alias: two profiles that differ only
 * in the key (a read-only key behind a strict gate, and another behind a lax one) must never share one.
 */
export function socketKeyOf(target: SshTarget, identityStamp = ""): string {
  return createHash("sha256")
    .update(JSON.stringify([target.host, target.user ?? null, target.port ?? null, target.identityFile ?? null, target.configFile ?? null, identityStamp]))
    .digest("hex")
    .slice(0, 12);
}

/**
 * The directory for the ssh connection-sharing sockets of ONE login, or null where sharing cannot work:
 * Windows, a path too long for a Unix socket, or characters ssh's option parser would split on.
 */
export function controlSocketDir(stateDir: string, platform: NodeJS.Platform, key: string): string | null {
  if (platform === "win32") return null;
  const dir = posix.join(stateDir, "cm", key); // a Unix socket path: always "/", also when tests run on Windows
  if (!controlPathFits(dir) || !/^[A-Za-z0-9._/-]+$/.test(dir)) return null;
  return dir;
}

/**
 * argv for the system ssh binary. The host was validated and cannot start with "-"; "--" stops ssh
 * from reading the remote command as options. Forwarding of every kind is switched off.
 */
export function buildSshArgs(target: SshTarget, remoteCommand: string, options: SshArgsOptions): string[] {
  if (target.host.startsWith("-") || /\s/.test(target.host)) throw new Error("invalid ssh host");
  const args = [
    "-T",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=4",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no",
  ];
  if (target.configFile !== undefined) args.push("-F", target.configFile);
  if (target.port !== undefined) args.push("-p", String(target.port));
  if (target.user !== undefined) args.push("-l", target.user);
  if (target.identityFile !== undefined) args.push("-i", target.identityFile, "-o", "IdentitiesOnly=yes");
  const socketDir = options.multiplex === false ? null : controlSocketDir(options.stateDir, options.platform, socketKeyOf(target, options.identityStamp));
  if (socketDir !== null) {
    args.push("-o", "ControlMaster=auto", "-o", `ControlPath=${socketDir}/%C`, "-o", `ControlPersist=${CONTROL_PERSIST_SECONDS}`);
  }
  args.push(target.host, "--", remoteCommand);
  return args;
}

export class SshTransport implements Transport {
  readonly label: string;
  private readonly target: SshTarget;
  private options: SshArgsOptions;
  private readonly prepared = new Set<string>();

  constructor(target: SshTarget, options: SshArgsOptions) {
    this.target = target;
    this.options = options;
    this.label = `ssh ${target.host}`;
  }

  run(request: RunRequest): Promise<RunResult> {
    const stamp = this.identityStamp();
    this.prepareSocketDir(stamp); // may switch sharing off
    const options: SshArgsOptions = { ...this.options, identityStamp: stamp };
    const fixed = request.fixedWords;
    const remote = request.argv
      .map((word, index) => (index < fixed ? word : quoteWord(word)))
      .join(" ");
    return runProcess("ssh", buildSshArgs(this.target, remote, options), { timeoutMs: request.timeoutMs });
  }

  /** What identifies the key file as it is now: replace the file and the stamp, and with it the connection, changes. */
  private identityStamp(): string {
    const file = this.target.identityFile;
    if (file === undefined) return "";
    try {
      const stat = statSync(file);
      return `${stat.size}:${Math.round(stat.mtimeMs)}:${stat.ino}`;
    } catch {
      return "unreadable";
    }
  }

  /** ssh does not create the directory of a ControlPath: do it once per login, privately, or do without sharing. */
  private prepareSocketDir(stamp: string): void {
    if (this.options.multiplex === false) return;
    const dir = controlSocketDir(this.options.stateDir, this.options.platform, socketKeyOf(this.target, stamp));
    if (dir === null || this.prepared.has(dir)) return;
    try {
      ensurePrivateDir(dirname(dir));
      ensurePrivateDir(dir);
      this.prepared.add(dir);
    } catch {
      this.options = { ...this.options, multiplex: false };
    }
  }
}

function quoteWord(word: string): string {
  if (word.includes("\0")) throw new Error("a NUL byte is not allowed");
  return `'${word.replaceAll("'", "'\\''")}'`;
}

export class LocalTransport implements Transport {
  readonly label = "local";

  run(request: RunRequest): Promise<RunResult> {
    const [file, ...args] = request.argv;
    if (file === undefined) throw new Error("empty command");
    return runProcess(file, args, { timeoutMs: request.timeoutMs });
  }
}

export interface TransportFactory {
  forProfile(profile: Profile): Transport;
  forSiteUser(profile: Profile, siteUser: string): Transport | null;
}

export function defaultTransports(stateDir: string, platform: NodeJS.Platform = process.platform): TransportFactory {
  const sshOptions: SshArgsOptions = { stateDir, platform };
  return {
    forProfile(profile) {
      return profile.target.kind === "local" ? new LocalTransport() : new SshTransport(profile.target.ssh, sshOptions);
    },
    forSiteUser(profile, siteUser) {
      // own properties only: "constructor" must not find Object on the prototype chain
      const target = Object.hasOwn(profile.siteUserAccess, siteUser) ? profile.siteUserAccess[siteUser] : undefined;
      return target === undefined ? null : new SshTransport(target, sshOptions);
    },
  };
}

/** Re-exported so tests can assert the rendered remote command without a transport. */
export { renderRemoteCommand };
