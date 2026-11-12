#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { buildCatalog } from "./catalog/index.ts";
import { ConfigError, loadConfig, nodeVersionOk } from "./config/load.ts";
import type { Config } from "./config/types.ts";
import { AuditLog } from "./audit.ts";
import { Detector } from "./detect.ts";
import { checkConnection } from "./doctor.ts";
import { bundleServerSetup } from "./setup.ts";
import { initConfigPath, initConfigText, parseInitArgs, writeInitConfig } from "./init.ts";
import { Engine } from "./engine.ts";
import { killActive } from "./exec/process.ts";
import { defaultTransports } from "./exec/transport.ts";
import { createServerFactory } from "./mcp/server.ts";
import { RateLimiter } from "./policy/rate.ts";
import { profileWarnings } from "./policy/warnings.ts";
import { PlanTokens } from "./policy/tokens.ts";
import { Redactor } from "./secrets/redact.ts";
import { SecretsStore } from "./secrets/store.ts";
import { FILE_SUBDIR, FILE_KINDS, kindDirs, portRangesText } from "./validate/patterns.ts";

// stdout belongs to the MCP protocol. Everything human-readable goes to stderr.
function log(message: string): void {
  process.stderr.write(`cloudpanel-mcp-server: ${message}\n`);
}

function readVersion(): string {
  try {
    const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8");
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const HELP = `cloudpanel-mcp-server - an unofficial MCP server for CloudPanel v2 (stdio)

Usage: cloudpanel-mcp-server [--version] [--help] [--check-config] [--check-connection] [--print-server-setup]
       cloudpanel-mcp-server --init --host <address|alias> [--user cloudpanel-mcp] [--identity-file ~/.ssh/id_ed25519_cloudpanel]
                             [--port 22] [--allow read|write[,destructive][,admin]] [--profile default]

  --init                write the configuration file for one server (never over an existing file),
                        then check the connection; MCP clients then need no setting at all
  --check-config        read the configuration, print what it means (no secrets), and exit
  --check-connection    log in to each configured server, run the read-only clpctl usage listing,
                        and say what is wrong if it fails (nothing is changed)
  --print-server-setup  print the script that prepares a CloudPanel server (account, sudo line,
                        directories, gate, key); send it with:  ... | ssh root@<server> "bash -s -- --key '...'"
  --version             print the version
  --help                print this text

It is started by an MCP client, not by hand. Configuration: a JSON file
(CLOUDPANEL_MCP_CONFIG, default in your config directory) or CLOUDPANEL_MCP_* variables.
See docs/CONFIGURATION.md and docs/SETUP.md.
`;

function describeConfig(config: Config): string {
  const lines = [`configuration: ${config.source}`, `state directory: ${config.stateDir}`];
  for (const p of config.profiles) {
    const where = p.target.kind === "local" ? "local" : `ssh ${p.target.ssh.host}${p.target.ssh.user ? ` as ${p.target.ssh.user}` : ""}${p.target.ssh.port ? ` port ${p.target.ssh.port}` : ""}`;
    lines.push(
      `profile ${p.name}: ${where}; elevation ${p.elevation}; classes: read${[...p.allow].map((c) => `, ${c}`).join("")}; approval for write: ${p.approvalWrite}`,
      `  protected domains: ${p.protect.domains.join(", ") || "(none)"}; protected site users: ${p.protect.siteUsers.join(", ") || "(none)"}; databases: ${p.protect.databases.join(", ") || "(none)"}; panel users: ${p.protect.panelUsers.join(", ") || "(none)"}`,
      `  file directories: ${p.fileDirs.join(", ")} (a profile reads and writes ${FILE_KINDS.map((k) => `${kindDirs(k, p.fileDirs).join(" ")} [${FILE_SUBDIR[k]}]`).join(", ")})`,
      `  application ports: ${portRangesText(p.appPorts)}; reverse-proxy hosts: ${p.proxyHosts.join(", ")}`,
      ...profileWarnings(p).map((w) => `  WARNING: ${w}`),
    );
  }
  return lines.join("\n");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    process.stdout.write(HELP);
    return;
  }
  if (args.includes("--version")) {
    process.stdout.write(`${readVersion()}\n`);
    return;
  }
  if (!nodeVersionOk(process.versions.node)) {
    log(`Node 22 or newer is required (this is ${process.versions.node}); register the server with the absolute path of a Node 22+ binary`);
    process.exit(2);
  }
  if (args.includes("--init")) {
    try {
      const options = parseInitArgs(args);
      const path = initConfigPath(process.env);
      const written = writeInitConfig(path, initConfigText(options), process.env);
      process.stdout.write(`wrote ${path} (mode 600): profile ${options.profile}, ssh ${options.user}@${options.host}, classes: read${options.allow.map((c) => `, ${c}`).join("")}\n`);
      process.stdout.write("checking the connection...\n");
      const report = await checkConnection(written.profiles[0] as Config["profiles"][number], defaultTransports(written.stateDir));
      process.stdout.write(`${report.lines.join("\n")}\n`);
      process.stdout.write(
        report.ok
          ? "ready: register `npx -y cloudpanel-mcp-server@<version>` in your AI client (docs/CLIENTS.md); it needs no other setting.\n".replace("<version>", readVersion())
          : "fix what the hint says, then run --check-connection again; the file is kept.\n",
      );
      process.exitCode = report.ok ? 0 : 1;
    } catch (error) {
      if (error instanceof ConfigError) {
        log(error.message);
        process.exit(2);
      }
      throw error;
    }
    return;
  }
  if (args.includes("--print-server-setup")) {
    const read = (path: string): string => readFileSync(new URL(path, import.meta.url), "utf8");
    process.stdout.write(
      bundleServerSetup(read("../hardening/cloudpanel-mcp-setup.sh"), read("../hardening/cloudpanel-mcp-gate.sh"), read("../inventory/cloudpanel-mcp-inventory"), readVersion()),
    );
    return;
  }
  let config: Config;
  try {
    config = loadConfig({ env: process.env });
  } catch (error) {
    if (error instanceof ConfigError) {
      log(`configuration error: ${error.message}`);
      process.exit(2);
    }
    throw error;
  }
  if (args.includes("--check-config")) {
    process.stdout.write(`${describeConfig(config)}\n`);
    return;
  }
  if (args.includes("--check-connection")) {
    const transports = defaultTransports(config.stateDir);
    let allOk = true;
    for (const profile of config.profiles) {
      const report = await checkConnection(profile, transports);
      allOk &&= report.ok;
      process.stdout.write(`${report.lines.join("\n")}\n`);
    }
    process.exitCode = allOk ? 0 : 1;
    return;
  }

  const redactor = new Redactor();
  const audit = new AuditLog(config.stateDir, redactor);
  const secretStores = new Map<string, SecretsStore>();
  const transports = defaultTransports(config.stateDir);
  const version = readVersion();
  const engine = new Engine({
    profiles: config.profiles,
    defaultProfile: config.defaultProfile,
    catalog: buildCatalog(),
    transports,
    audit,
    redactor,
    secretsFor: (profile) => {
      let store = secretStores.get(profile);
      if (store === undefined) {
        store = new SecretsStore(config.stateDir, profile);
        secretStores.set(profile, store);
      }
      return store;
    },
    limiter: new RateLimiter(),
    tokens: new PlanTokens(),
    detector: new Detector(transports),
    serverVersion: version,
  });
  try {
    audit.record({ event: "server", note: `started ${version}; profiles ${config.profiles.map((p) => p.name).join(",")}; tools ${engine.toolNames.length}` });
  } catch {
    log("warning: the audit log cannot be written; changing tools will refuse to run");
  }

  const handle = serveStdio(createServerFactory(engine, version));
  const shutdown = (): void => {
    killActive();
    try {
      audit.flush(); // the count of records held back in the running minute
    } catch {
      // the log cannot be written: nothing more to do on the way out
    }
    void handle.close().finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  log(`${version} ready: profiles=${config.profiles.map((p) => p.name).join(",")} tools=${engine.toolNames.length}`);
}

main().catch((error: unknown) => {
  log(`fatal: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
