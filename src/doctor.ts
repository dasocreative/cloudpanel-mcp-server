import type { Profile } from "./config/types.ts";
import { buildArgv } from "./exec/quote.ts";
import { parseUsageListing, sanitize } from "./exec/output.ts";
import type { RunResult } from "./exec/process.ts";
import type { TransportFactory } from "./exec/transport.ts";

/**
 * `--check-connection`: run the read-only usage listing (`[sudo -n] clpctl`, exactly what the server's
 * feature detection runs) once per profile and say, in plain words, what is wrong when it fails.
 * Nothing is changed on the server.
 */

const CHECK_TIMEOUT_MS = 30_000;

export interface ConnectionReport {
  readonly profile: string;
  readonly ok: boolean;
  readonly lines: readonly string[];
}

/** One plain-language hint for a failed probe, from what ssh, sudo, the gate or clpctl printed. */
export function diagnose(result: RunResult, profile: Profile): string {
  const err = sanitize(`${result.stderr}\n${result.spawnError ?? ""}`);
  const via = profile.target.kind === "local" ? "" : ` (${describeTarget(profile)})`;
  if (result.spawnError !== undefined && /ENOENT/.test(result.spawnError)) {
    return profile.target.kind === "local"
      ? `the program was not found: check CLOUDPANEL_MCP_CLPCTL_PATH (now ${profile.clpctlPath})`
      : "the ssh program was not found: install the OpenSSH client";
  }
  if (/Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|No .* host key is known/i.test(err)) {
    return `the server's host key is not known on this machine (or it changed): log in once by hand${via} and answer "yes", then try again`;
  }
  if (/Permission denied \((publickey|password|keyboard-interactive)/i.test(err)) {
    return "the server refused the key: check the user (CLOUDPANEL_MCP_SSH_USER), the private key file (CLOUDPANEL_MCP_SSH_IDENTITY_FILE) and that its PUBLIC key is in that account's authorized_keys (the setup script's --key); if sshd has an AllowUsers line, the account must be on it";
  }
  if (/Could not resolve hostname|Name or service not known|nodename nor servname/i.test(err)) {
    return "the host name does not resolve: check CLOUDPANEL_MCP_SSH_HOST (an address, a DNS name or an alias of ~/.ssh/config)";
  }
  if (/Connection refused|Connection timed out|No route to host|Network is unreachable|Operation timed out/i.test(err)) {
    return "the server cannot be reached on its SSH port: check the address, the port (CLOUDPANEL_MCP_SSH_PORT) and the firewalls on the way";
  }
  if (/cloudpanel-mcp-gate: refused/i.test(err)) {
    return "the gate on the server refused the call: its settings (CLPCTL path, class ceilings) must match this profile; see /usr/local/sbin/cloudpanel-mcp-gate.sh";
  }
  if (/password is required|a terminal is required|askpass/i.test(err)) {
    return `sudo asks for a password: the account needs the sudoers line "<user> ALL=(root) NOPASSWD: ${profile.clpctlPath}" (the setup script writes it)`;
  }
  if (/not in the sudoers file|is not allowed to execute|may not run sudo/i.test(err)) {
    return `the account may not run ${profile.clpctlPath} through sudo: check /etc/sudoers.d/cloudpanel-mcp-server and the clpctl path`;
  }
  if (/(clpctl|No such file or directory|command not found|not found)/i.test(err) && result.exitCode === 127) {
    return `clpctl was not found at ${profile.clpctlPath} on the server: set CLOUDPANEL_MCP_CLPCTL_PATH to the output of "command -v clpctl" there`;
  }
  if (result.timedOut) {
    return "no answer in 30 seconds: usually a prompt nobody can answer (a key passphrase, a host key question). The key must work with no prompt: load it into ssh-agent, or use a dedicated key without passphrase pinned to the gate";
  }
  if (result.exitCode === 0) {
    return "clpctl answered, but not with its usage listing: is this a CloudPanel v2 server, and is the clpctl path right?";
  }
  return "see the message above";
}

function describeTarget(profile: Profile): string {
  if (profile.target.kind === "local") return "local";
  const s = profile.target.ssh;
  const login = `${s.user !== undefined ? `${s.user}@` : ""}${s.host}`;
  return `ssh${s.port !== undefined ? ` -p ${s.port}` : ""}${s.identityFile !== undefined ? ` -i ${s.identityFile}` : ""} ${login}`;
}

/** The first few lines of what the other side printed, cleaned and bounded, for the report. */
function excerpt(text: string): string[] {
  return sanitize(text)
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.trim() !== "")
    .slice(0, 4)
    .map((l) => (l.length > 200 ? `${l.slice(0, 200)}...` : l));
}

export async function checkConnection(profile: Profile, transports: TransportFactory): Promise<ConnectionReport> {
  const where = describeTarget(profile);
  const prefix = profile.elevation === "sudo" ? ["sudo", "-n"] : [];
  let result: RunResult;
  try {
    const argv = buildArgv({ prefix, clpctlPath: profile.clpctlPath, tokens: [] });
    result = await transports.forProfile(profile).run({ argv, fixedWords: argv.length, timeoutMs: Math.min(profile.timeouts.defaultMs, CHECK_TIMEOUT_MS) });
  } catch (error) {
    const message = error instanceof Error ? sanitize(error.message).slice(0, 200) : "the check could not start";
    return { profile: profile.name, ok: false, lines: [`profile ${profile.name} (${where}): FAILED`, `  ${message}`] };
  }
  const listing = parseUsageListing(result.stdout);
  if (listing.length > 0) {
    return {
      profile: profile.name,
      ok: true,
      lines: [`profile ${profile.name} (${where}): ok - ${profile.elevation === "sudo" ? "sudo -n " : ""}${profile.clpctlPath} answered with ${listing.length} commands`],
    };
  }
  const status = result.timedOut ? "timed out" : result.exitCode === null ? `ended by ${result.signal ?? "a signal"}` : `exit status ${result.exitCode}`;
  return {
    profile: profile.name,
    ok: false,
    lines: [
      `profile ${profile.name} (${where}): FAILED (${status})`,
      ...excerpt(result.stderr || result.stdout).map((l) => `  | ${l}`),
      `  hint: ${diagnose(result, profile)}`,
    ],
  };
}
