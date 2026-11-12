import type { ChangingClass } from "../policy/classes.ts";
import type { PortRange } from "../validate/patterns.ts";

export interface SshTarget {
  /** An ssh_config alias, a host name or an address. Never starts with "-". */
  readonly host: string;
  readonly user?: string | undefined;
  readonly port?: number | undefined;
  readonly identityFile?: string | undefined;
  readonly configFile?: string | undefined;
}

export type Target =
  | { readonly kind: "ssh"; readonly ssh: SshTarget }
  | { readonly kind: "local" };

export interface RateLimit {
  readonly max: number;
  readonly perMinutes: number;
}

/** Calls per class, plus `ask`: how many approval questions the human may be put per window, answered or not. */
export type RateLimits = Readonly<Record<ChangingClass | "ask", RateLimit>>;

export interface Protect {
  /** Exact domains, or "*.suffix". */
  readonly domains: readonly string[];
  readonly siteUsers: readonly string[];
  readonly databases: readonly string[];
  readonly panelUsers: readonly string[];
}

export interface Timeouts {
  readonly defaultMs: number;
  readonly letsEncryptMs: number;
  readonly dbMs: number;
}

export interface Profile {
  readonly name: string;
  readonly target: Target;
  /** "sudo": run `sudo -n <clpctl>`; "none": the account is root or already privileged. */
  readonly elevation: "sudo" | "none";
  readonly clpctlPath: string;
  /** READ is always allowed and is not listed here. */
  readonly allow: ReadonlySet<ChangingClass>;
  readonly approvalWrite: "ask" | "client";
  readonly protect: Protect;
  readonly fileDirs: readonly string[];
  /** fileDirs may be in places other accounts can write (throw-away test servers only). */
  readonly allowUntrustedFileDirs: boolean;
  readonly proxyHosts: readonly string[];
  /** Ports a Node.js or Python app, or a reverse-proxy upstream, may use (never the denied ports). */
  readonly appPorts: readonly PortRange[];
  /** site user -> how to log in as that user */
  readonly siteUserAccess: Readonly<Record<string, SshTarget>>;
  readonly inventory: { readonly enabled: boolean; readonly command: string };
  readonly rateLimits: RateLimits;
  readonly timeouts: Timeouts;
}

export interface Config {
  readonly profiles: readonly Profile[];
  readonly defaultProfile: string;
  readonly stateDir: string;
  /** Where the configuration came from, for `--check-config`. */
  readonly source: string;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}
