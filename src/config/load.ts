import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { posix, win32 } from "node:path";
import * as z from "zod/v4";
import { CHANGING_CLASSES, type ChangingClass } from "../policy/classes.ts";
import { DEFAULT_APP_PORTS, FORBIDDEN_DIR_ROOTS, RE, SHARED_DIR_ROOTS, isCleanPath, isDomain, isPortAllowedAtAll, underRoot, type PortRange } from "../validate/patterns.ts";
import { defaultConfigPath, defaultStateDir, expandHome } from "./paths.ts";
import {
  ConfigError,
  type Config,
  type Profile,
  type RateLimit,
  type RateLimits,
  type SshTarget,
} from "./types.ts";

export { ConfigError } from "./types.ts";

type Env = Readonly<Record<string, string | undefined>>;

export const DEFAULT_CLPCTL_PATH = "/usr/bin/clpctl";
export const DEFAULT_FILE_DIRS: readonly string[] = ["/var/lib/cloudpanel-mcp-server"];
export const DEFAULT_PROXY_HOSTS: readonly string[] = ["127.0.0.1", "localhost", "::1"];
export const DEFAULT_INVENTORY_COMMAND = "/usr/local/sbin/cloudpanel-mcp-inventory";
export const DEFAULT_RATE_LIMITS: RateLimits = {
  write: { max: 20, perMinutes: 10 },
  destructive: { max: 3, perMinutes: 10 },
  admin: { max: 5, perMinutes: 10 },
  ask: { max: 30, perMinutes: 10 },
};
const DEFAULT_TIMEOUTS_S = { default: 120, letsEncrypt: 600, db: 600 } as const;

const PROFILE_NAME = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const SSH_HOST = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$/;
const SSH_USER = /^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/;
const HOST_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;
const IPV6_RE = /^[0-9a-f:]{2,39}$/;
const DOMAIN_PATTERN = /^\*\.([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;


function pathString(what: string): z.ZodType<string> {
  return z
    .string()
    .min(1)
    .max(1024)
    .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), `${what} must not contain control characters`);
}

const sshObject = z.strictObject({
  host: z.string().regex(SSH_HOST, "must be a host name, address or ssh_config alias that does not start with - or ."),
  user: z.string().regex(SSH_USER, "must be a plain account name").optional(),
  port: z.number().int().min(1).max(65535).optional(),
  identityFile: pathString("identityFile").optional(),
  configFile: pathString("configFile").optional(),
});

const rateTuple = z.tuple([z.number().int().min(1).max(1000), z.number().int().min(1).max(1440)]);

const profileSchema = z.strictObject({
  ssh: sshObject.optional(),
  local: z.boolean().optional(),
  elevation: z.enum(["sudo", "none"]).optional(),
  clpctlPath: z.string().optional(),
  allow: z.array(z.enum(["write", "destructive", "admin"])).max(3).optional(),
  approval: z.strictObject({ write: z.enum(["ask", "client"]).optional() }).optional(),
  protect: z
    .strictObject({
      domains: z.array(z.string()).max(500).optional(),
      siteUsers: z.array(z.string()).max(500).optional(),
      databases: z.array(z.string()).max(500).optional(),
      panelUsers: z.array(z.string()).max(500).optional(),
    })
    .optional(),
  fileDirs: z.array(z.string()).min(1).max(20).optional(),
  allowUntrustedFileDirs: z.boolean().optional(),
  proxyHosts: z.array(z.string()).min(1).max(50).optional(),
  appPorts: z.array(z.union([z.number(), z.string()])).min(1).max(50).optional(),
  siteUserAccess: z.record(z.string(), z.union([z.string(), sshObject])).optional(),
  inventory: z
    .union([z.boolean(), z.strictObject({ enabled: z.boolean(), command: z.string().optional() })])
    .optional(),
  rateLimits: z
    .strictObject({
      write: rateTuple.optional(),
      destructive: rateTuple.optional(),
      admin: rateTuple.optional(),
      ask: rateTuple.optional(),
    })
    .optional(),
  timeoutsSeconds: z
    .strictObject({
      default: z.number().int().min(5).max(3600).optional(),
      letsEncrypt: z.number().int().min(5).max(3600).optional(),
      db: z.number().int().min(5).max(3600).optional(),
    })
    .optional(),
});

const configSchema = z.strictObject({
  profiles: z.record(z.string(), profileSchema),
  defaultProfile: z.string().optional(),
});

type RawProfile = z.infer<typeof profileSchema>;
type RawSsh = z.infer<typeof sshObject>;

function fail(path: string, message: string): never {
  throw new ConfigError(`${path}: ${message}`);
}

function describeIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 8)
    .map((issue) => {
      const where = issue.path.map(String).join(".") || "(root)";
      const what =
        issue.code === "unrecognized_keys"
          ? `unknown key(s): ${issue.keys.join(", ")}`
          : issue.message;
      return `${where}: ${what}`;
    })
    .join("; ");
}

function cleanDir(path: string, where: string, allowShared: boolean): string {
  const segments = path.split("/").filter((s) => s !== "");
  if (!isCleanPath(path) || segments.length < 2) {
    fail(where, 'must be an absolute directory at least two levels deep, without trailing slash, ".." or special characters');
  }
  if (underRoot(path, FORBIDDEN_DIR_ROOTS)) {
    fail(where, `must not be inside ${FORBIDDEN_DIR_ROOTS.join(", ")}`);
  }
  if (!allowShared && underRoot(path, SHARED_DIR_ROOTS)) {
    fail(
      where,
      `must not be inside ${SHARED_DIR_ROOTS.join(", ")}: other accounts can write there, and root-run clpctl follows the symbolic links they plant. Use a root-owned directory such as /var/lib/cloudpanel-mcp-server (allowUntrustedFileDirs accepts this on a throw-away test server only)`,
    );
  }
  return path;
}

/** "3000", 3000 or "3000-3999": above 1023, a range runs upward, and a single denied port is refused outright. */
function appPortRange(value: number | string, where: string): PortRange {
  const m = /^([0-9]{1,5})(?:-([0-9]{1,5}))?$/.exec(String(value));
  if (m === null) fail(where, 'must be a port such as 3000 or a range such as "3000-3999"');
  const from = Number(m[1]);
  const to = m[2] === undefined ? from : Number(m[2]);
  if (!(from >= 1024 && to <= 65535 && from <= to)) fail(where, "ports run from 1024 to 65535 and a range runs upward");
  if (m[2] === undefined && !isPortAllowedAtAll(from)) {
    fail(where, `port ${from} is never allowed (databases, caches, queues, admin APIs and the panel)`);
  }
  return { from, to };
}

function proxyHost(value: string, where: string): string {
  const host = value.toLowerCase();
  const ok =
    (host.includes(":") && IPV6_RE.test(host)) ||
    (!host.includes(":") && HOST_RE.test(host));
  if (!ok) fail(where, "must be a lowercase host name or an IPv6 literal without brackets");
  return host;
}

const isAbsoluteOn = (platform: NodeJS.Platform, path: string): boolean => (platform === "win32" ? win32 : posix).isAbsolute(path);

function resolveSsh(raw: RawSsh, home: string, where: string, platform: NodeJS.Platform): SshTarget {
  const identityFile = raw.identityFile === undefined ? undefined : expandHome(raw.identityFile, home, platform);
  const configFile = raw.configFile === undefined ? undefined : expandHome(raw.configFile, home, platform);
  for (const [key, value] of [["identityFile", identityFile], ["configFile", configFile]] as const) {
    if (value !== undefined && !isAbsoluteOn(platform, value)) fail(`${where}.${key}`, "must be an absolute path (or start with ~/)");
  }
  return {
    host: raw.host,
    user: raw.user,
    port: raw.port,
    identityFile,
    configFile,
  };
}

function buildProfile(name: string, raw: RawProfile, home: string, platform: NodeJS.Platform): Profile {
  const where = `profiles.${name}`;
  if (!PROFILE_NAME.test(name)) fail(where, "the profile name must match ^[a-z0-9][a-z0-9_-]{0,31}$");
  const hasSsh = raw.ssh !== undefined;
  const isLocal = raw.local === true;
  if (hasSsh === isLocal) fail(where, 'give exactly one of "ssh" (a remote server) or "local": true (this machine is the CloudPanel host)');
  const target = hasSsh
    ? ({ kind: "ssh", ssh: resolveSsh(raw.ssh as RawSsh, home, `${where}.ssh`, platform) } as const)
    : ({ kind: "local" } as const);

  const clpctlPath = raw.clpctlPath ?? DEFAULT_CLPCTL_PATH;
  if (!isCleanPath(clpctlPath)) fail(`${where}.clpctlPath`, "must be a clean absolute path");

  const allow = new Set<ChangingClass>();
  for (const cls of raw.allow ?? []) {
    if (!CHANGING_CLASSES.includes(cls)) fail(`${where}.allow`, "unknown class");
    allow.add(cls);
  }

  const protect = {
    domains: (raw.protect?.domains ?? []).map((d, i) => {
      if (!isDomain(d) && !DOMAIN_PATTERN.test(d)) fail(`${where}.protect.domains[${i}]`, 'must be a lowercase domain or "*.suffix"');
      return d;
    }),
    siteUsers: (raw.protect?.siteUsers ?? []).map((u, i) => {
      if (!RE.siteUser.test(u)) fail(`${where}.protect.siteUsers[${i}]`, "must be a valid site user name");
      return u;
    }),
    databases: (raw.protect?.databases ?? []).map((d, i) => {
      if (!RE.dbName.test(d)) fail(`${where}.protect.databases[${i}]`, "must be a valid database name");
      return d;
    }),
    panelUsers: (raw.protect?.panelUsers ?? []).map((u, i) => {
      if (!RE.panelUser.test(u)) fail(`${where}.protect.panelUsers[${i}]`, "must be a valid panel user name");
      return u;
    }),
  };

  const allowUntrustedFileDirs = raw.allowUntrustedFileDirs === true;
  const fileDirs = (raw.fileDirs ?? DEFAULT_FILE_DIRS).map((d, i) => cleanDir(d, `${where}.fileDirs[${i}]`, allowUntrustedFileDirs));
  const proxyHosts = (raw.proxyHosts ?? DEFAULT_PROXY_HOSTS).map((h, i) => proxyHost(h, `${where}.proxyHosts[${i}]`));
  const appPorts = raw.appPorts === undefined ? DEFAULT_APP_PORTS : raw.appPorts.map((p, i) => appPortRange(p, `${where}.appPorts[${i}]`));

  const siteUserAccess: Record<string, SshTarget> = {};
  for (const [siteUser, access] of Object.entries(raw.siteUserAccess ?? {})) {
    if (!RE.siteUser.test(siteUser)) fail(`${where}.siteUserAccess`, `"${siteUser.slice(0, 40)}" is not a valid site user name`);
    const parsed = typeof access === "string" ? sshObject.safeParse({ host: access }) : sshObject.safeParse(access);
    if (!parsed.success) fail(`${where}.siteUserAccess.${siteUser}`, describeIssues(parsed.error));
    // the label is what the server and the human see; the login must be that site user, not root or another account
    if (parsed.data.user !== undefined && parsed.data.user !== siteUser) {
      fail(`${where}.siteUserAccess.${siteUser}`, `the ssh user must be the site user itself (${siteUser}), not "${parsed.data.user.slice(0, 40)}"`);
    }
    siteUserAccess[siteUser] = resolveSsh(parsed.data, home, `${where}.siteUserAccess.${siteUser}`, platform);
  }

  const inv = raw.inventory;
  const invEnabled = inv === undefined ? false : typeof inv === "boolean" ? inv : inv.enabled;
  const invCommand = typeof inv === "object" && inv.command !== undefined ? inv.command : DEFAULT_INVENTORY_COMMAND;
  if (!isCleanPath(invCommand)) fail(`${where}.inventory.command`, "must be a clean absolute path");

  const limit = (cls: ChangingClass | "ask"): RateLimit => {
    const value = raw.rateLimits?.[cls];
    return value === undefined ? DEFAULT_RATE_LIMITS[cls] : { max: value[0], perMinutes: value[1] };
  };
  const t = { ...DEFAULT_TIMEOUTS_S, ...stripUndefined(raw.timeoutsSeconds ?? {}) };

  return Object.freeze({
    name,
    target,
    elevation: raw.elevation ?? "sudo",
    clpctlPath,
    allow,
    approvalWrite: raw.approval?.write ?? "ask",
    protect,
    fileDirs: Object.freeze([...new Set(fileDirs)]),
    allowUntrustedFileDirs,
    proxyHosts: Object.freeze([...new Set(proxyHosts)]),
    appPorts: Object.freeze(appPorts),
    siteUserAccess: Object.freeze(siteUserAccess),
    inventory: { enabled: invEnabled, command: invCommand },
    rateLimits: { write: limit("write"), destructive: limit("destructive"), admin: limit("admin"), ask: limit("ask") },
    timeouts: { defaultMs: t.default * 1000, letsEncryptMs: t.letsEncrypt * 1000, dbMs: t.db * 1000 },
  });
}

function stripUndefined<T extends Record<string, number | undefined>>(o: T): Record<string, number> {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Record<string, number>;
}

/** The environment quick start: one profile out of CLOUDPANEL_MCP_* variables. Unknown names are refused. */
export const ENV_NAMES = new Set([
  "CONFIG", "STATE_DIR", "PROFILE", "SSH_HOST", "SSH_USER", "SSH_PORT", "SSH_IDENTITY_FILE", "SSH_CONFIG_FILE",
  "LOCAL", "ELEVATION", "CLPCTL_PATH", "ALLOW", "APPROVAL_WRITE", "PROTECT_DOMAINS", "PROTECT_SITE_USERS",
  "PROTECT_DATABASES", "PROTECT_PANEL_USERS", "FILE_DIRS", "PROXY_HOSTS", "APP_PORTS", "INVENTORY", "INVENTORY_COMMAND",
]);

function list(value: string | undefined): string[] | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  return value.split(",").map((part) => part.trim());
}

function flag(env: Env, name: string): boolean | undefined {
  const value = env[name];
  if (value === undefined || value === "") return undefined;
  if (value === "1") return true;
  if (value === "0") return false;
  throw new ConfigError(`${name} must be 0 or 1`);
}

function rawProfileFromEnv(env: Env): { name: string; raw: Record<string, unknown> } {
  const raw: Record<string, unknown> = {};
  const host = env["CLOUDPANEL_MCP_SSH_HOST"];
  if (host !== undefined && host !== "") {
    const ssh: Record<string, unknown> = { host };
    if (env["CLOUDPANEL_MCP_SSH_USER"]) ssh["user"] = env["CLOUDPANEL_MCP_SSH_USER"];
    if (env["CLOUDPANEL_MCP_SSH_PORT"]) {
      const port = Number(env["CLOUDPANEL_MCP_SSH_PORT"]);
      ssh["port"] = port;
    }
    if (env["CLOUDPANEL_MCP_SSH_IDENTITY_FILE"]) ssh["identityFile"] = env["CLOUDPANEL_MCP_SSH_IDENTITY_FILE"];
    if (env["CLOUDPANEL_MCP_SSH_CONFIG_FILE"]) ssh["configFile"] = env["CLOUDPANEL_MCP_SSH_CONFIG_FILE"];
    raw["ssh"] = ssh;
  }
  if (flag(env, "CLOUDPANEL_MCP_LOCAL") === true) raw["local"] = true;
  if (env["CLOUDPANEL_MCP_ELEVATION"]) raw["elevation"] = env["CLOUDPANEL_MCP_ELEVATION"];
  if (env["CLOUDPANEL_MCP_CLPCTL_PATH"]) raw["clpctlPath"] = env["CLOUDPANEL_MCP_CLPCTL_PATH"];
  const allow = list(env["CLOUDPANEL_MCP_ALLOW"]);
  if (allow !== undefined) raw["allow"] = allow;
  if (env["CLOUDPANEL_MCP_APPROVAL_WRITE"]) raw["approval"] = { write: env["CLOUDPANEL_MCP_APPROVAL_WRITE"] };
  const protect: Record<string, string[]> = {};
  for (const [key, name] of [["domains", "PROTECT_DOMAINS"], ["siteUsers", "PROTECT_SITE_USERS"], ["databases", "PROTECT_DATABASES"], ["panelUsers", "PROTECT_PANEL_USERS"]] as const) {
    const values = list(env[`CLOUDPANEL_MCP_${name}`]);
    if (values !== undefined) protect[key] = values;
  }
  if (Object.keys(protect).length > 0) raw["protect"] = protect;
  const dirs = list(env["CLOUDPANEL_MCP_FILE_DIRS"]);
  if (dirs !== undefined) raw["fileDirs"] = dirs;
  const hosts = list(env["CLOUDPANEL_MCP_PROXY_HOSTS"]);
  if (hosts !== undefined) raw["proxyHosts"] = hosts;
  const ports = list(env["CLOUDPANEL_MCP_APP_PORTS"]);
  if (ports !== undefined) raw["appPorts"] = ports;
  const inv = flag(env, "CLOUDPANEL_MCP_INVENTORY");
  if (inv !== undefined) {
    raw["inventory"] = env["CLOUDPANEL_MCP_INVENTORY_COMMAND"] ? { enabled: inv, command: env["CLOUDPANEL_MCP_INVENTORY_COMMAND"] } : inv;
  }
  return { name: env["CLOUDPANEL_MCP_PROFILE"] || "default", raw };
}

export interface LoadOptions {
  readonly env: Env;
  readonly platform?: NodeJS.Platform;
  readonly home?: string;
  /** Test seam. */
  readonly readFile?: (path: string) => string;
  readonly fileMode?: (path: string) => number | null;
}

function defaultReadFile(path: string): string {
  return readFileSync(path, "utf8");
}

function defaultFileMode(path: string): number | null {
  try {
    return statSync(path).mode;
  } catch {
    return null;
  }
}

export function loadConfig(options: LoadOptions): Config {
  const env = options.env;
  const platform = options.platform ?? process.platform;
  const home = options.home ?? homedir();
  const read = options.readFile ?? defaultReadFile;
  const modeOf = options.fileMode ?? defaultFileMode;

  for (const name of Object.keys(env)) {
    if (name.startsWith("CLOUDPANEL_MCP_") && !ENV_NAMES.has(name.slice("CLOUDPANEL_MCP_".length))) {
      throw new ConfigError(`unknown environment variable ${name} (a misspelt setting is refused, not ignored)`);
    }
  }

  const explicit = env["CLOUDPANEL_MCP_CONFIG"];
  const configPath = explicit !== undefined && explicit !== "" ? expandHome(explicit, home, platform) : defaultConfigPath(env, platform, home);
  const stateDirEnv = env["CLOUDPANEL_MCP_STATE_DIR"];
  const stateDir = stateDirEnv !== undefined && stateDirEnv !== "" ? expandHome(stateDirEnv, home, platform) : defaultStateDir(env, platform, home);
  if (!isAbsoluteOn(platform, stateDir)) throw new ConfigError("the state directory must be an absolute path");

  let rawConfig: { profiles: Record<string, RawProfile>; defaultProfile?: string | undefined };
  let source: string;
  const mode = modeOf(configPath);
  if (mode !== null) {
    if (platform !== "win32" && (mode & 0o022) !== 0) {
      throw new ConfigError(`${configPath} is writable by group or others: run chmod 600 on it (a config others can edit could widen what this server may do)`);
    }
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(read(configPath));
    } catch (error) {
      // the parser's own message can quote the text it choked on: say only where
      const at = error instanceof Error ? /position (\d{1,9})/.exec(error.message)?.[1] : undefined;
      throw new ConfigError(`${configPath} is not valid JSON${at === undefined ? "" : ` (near character ${at})`}`);
    }
    const parsed = configSchema.safeParse(parsedJson);
    if (!parsed.success) throw new ConfigError(`${configPath}: ${describeIssues(parsed.error)}`);
    rawConfig = parsed.data;
    source = configPath;
  } else {
    if (explicit !== undefined && explicit !== "") {
      throw new ConfigError(`CLOUDPANEL_MCP_CONFIG points to ${configPath}, which does not exist`);
    }
    const quick = rawProfileFromEnv(env);
    if (quick.raw["ssh"] === undefined && quick.raw["local"] === undefined) {
      throw new ConfigError(
        `no profile configured: create ${configPath}, or set CLOUDPANEL_MCP_SSH_HOST (an ssh alias) or CLOUDPANEL_MCP_LOCAL=1. See docs/CONFIGURATION.md.`,
      );
    }
    const parsed = profileSchema.safeParse(quick.raw);
    if (!parsed.success) throw new ConfigError(`environment: ${describeIssues(parsed.error)}`);
    rawConfig = { profiles: { [quick.name]: parsed.data } };
    source = "environment variables";
  }

  const names = Object.keys(rawConfig.profiles);
  if (names.length === 0) throw new ConfigError("profiles: at least one profile is required");
  const profiles = names.map((name) => buildProfile(name, rawConfig.profiles[name] as RawProfile, home, platform));
  const defaultProfile = rawConfig.defaultProfile ?? (profiles.length === 1 ? (profiles[0] as Profile).name : undefined);
  if (defaultProfile === undefined) {
    // several profiles and no default: the tools then require an explicit "profile"
  } else if (!profiles.some((p) => p.name === defaultProfile)) {
    throw new ConfigError(`defaultProfile "${defaultProfile.slice(0, 40)}" is not one of the profiles`);
  }
  return Object.freeze({
    profiles: Object.freeze(profiles),
    defaultProfile: defaultProfile ?? "",
    stateDir,
    source,
  });
}

/** The server needs Node 22 or newer. */
export function nodeVersionOk(version: string): boolean {
  const major = Number(version.split(".")[0]);
  return Number.isInteger(major) && major >= 22;
}
