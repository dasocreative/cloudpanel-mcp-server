import { writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { ConfigError, loadConfig } from "./config/load.ts";
import { defaultConfigPath, expandHome } from "./config/paths.ts";
import type { Config } from "./config/types.ts";
import { ensurePrivateDir } from "./fsutil.ts";

/**
 * `--init`: write the configuration file for one server, so that every MCP client can start the server
 * with no settings of its own (`npx -y cloudpanel-mcp-server@<version>`). It never overwrites a file.
 */

export interface InitOptions {
  readonly profile: string;
  readonly host: string;
  readonly user: string;
  readonly identityFile: string;
  readonly port: number | undefined;
  readonly allow: readonly string[];
}

const CLASSES = new Set(["write", "destructive", "admin"]);

export function parseInitArgs(args: readonly string[]): InitOptions {
  const values = new Map<string, string>();
  const known = new Set(["--host", "--user", "--identity-file", "--port", "--allow", "--profile"]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === "--init") continue;
    const eq = arg.indexOf("=");
    const name = eq > 0 ? arg.slice(0, eq) : arg;
    if (!known.has(name)) throw new ConfigError(`--init: unknown option ${arg.slice(0, 40)}`);
    const value = eq > 0 ? arg.slice(eq + 1) : args[++i];
    if (value === undefined || value === "") throw new ConfigError(`--init: ${name} needs a value`);
    values.set(name, value);
  }
  const host = values.get("--host");
  if (host === undefined) throw new ConfigError("--init needs --host <the server's address, DNS name or ssh alias>");
  const portText = values.get("--port");
  const port = portText === undefined ? undefined : Number(portText);
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new ConfigError("--init: --port must be 1-65535");
  const allow = (values.get("--allow") ?? "read")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "" && s !== "read");
  for (const c of allow) if (!CLASSES.has(c)) throw new ConfigError(`--init: --allow takes read, write, destructive or admin (comma-separated), not "${c.slice(0, 20)}"`);
  return {
    profile: values.get("--profile") ?? "default",
    host,
    user: values.get("--user") ?? "cloudpanel-mcp",
    identityFile: values.get("--identity-file") ?? "~/.ssh/id_ed25519_cloudpanel",
    port,
    allow: [...new Set(allow)],
  };
}

export function initConfigText(o: InitOptions): string {
  const ssh: Record<string, unknown> = { host: o.host, user: o.user, identityFile: o.identityFile };
  if (o.port !== undefined) ssh["port"] = o.port;
  const profile: Record<string, unknown> = { ssh, elevation: "sudo" };
  if (o.allow.length > 0) profile["allow"] = o.allow;
  profile["protect"] = { domains: [], siteUsers: [], databases: [], panelUsers: [] };
  return `${JSON.stringify({ profiles: { [o.profile]: profile }, defaultProfile: o.profile }, null, 2)}\n`;
}

/** Where --init writes: CLOUDPANEL_MCP_CONFIG, or the platform's default place. */
export function initConfigPath(env: NodeJS.ProcessEnv, platform: NodeJS.Platform = process.platform, home: string = homedir()): string {
  const explicit = env["CLOUDPANEL_MCP_CONFIG"];
  return explicit !== undefined && explicit !== "" ? expandHome(explicit, home, platform) : defaultConfigPath(env, platform, home);
}

/** Checks the text with the real loader, without touching the disk, then writes it (never over an existing file). */
export function writeInitConfig(path: string, text: string, env: NodeJS.ProcessEnv): Config {
  const check = (): Config =>
    loadConfig({
      env: { CLOUDPANEL_MCP_CONFIG: path, ...(env["CLOUDPANEL_MCP_STATE_DIR"] ? { CLOUDPANEL_MCP_STATE_DIR: env["CLOUDPANEL_MCP_STATE_DIR"] } : {}) },
      readFile: () => text,
      fileMode: () => 0o100600,
    });
  check(); // throws ConfigError on a value the server would refuse
  ensurePrivateDir(dirname(path));
  try {
    writeFileSync(path, text, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const entry = JSON.stringify((JSON.parse(text) as { profiles: unknown }).profiles, null, 2).slice(1, -1).trim();
      throw new ConfigError(
        `${path} already exists and is never overwritten. To add this server, paste this entry into its "profiles" (docs/CONFIGURATION.md):\n${entry}`,
      );
    }
    throw error;
  }
  return check();
}
