#!/usr/bin/env node
/**
 * Live contract test, for maintainers. It runs the tool families through the REAL built server against
 * a REAL CloudPanel, with throwaway names, acts as the human who approves each of its own steps, and
 * deletes everything it created. It exists to check this project's assumptions about `clpctl` on a
 * given CloudPanel release and to produce the table of docs/LIVE-VERIFICATION.md.
 *
 * NEVER point it at a server whose sites matter. It creates and deletes sites, databases, panel users,
 * certificates and vhost templates (and, with --include-panel, switches Basic Auth in front of the
 * panel on and off). It refuses to run without --i-understand-this-creates-and-deletes-things.
 *
 *   npm run build
 *   node scripts/contract-test.mjs --plan   --ssh-host my-server --file-dir /var/lib/contract-test
 *   node scripts/contract-test.mjs --i-understand-this-creates-and-deletes-things \
 *        --ssh-host my-server --file-dir /var/lib/contract-test [--only static,database] [--report out.md]
 *
 * --file-dir is a throwaway directory on the server that the ssh account may create and write (production
 * setups keep their file directory root-owned, see docs/SETUP.md). The server only reads and writes below its
 * subdirectories dumps/, certs/ and templates/; the script creates the ones that are missing, with mode 700,
 * and removes only those it created, and only if they are empty again.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, rmdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const value = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
};

const CONFIRM = "--i-understand-this-creates-and-deletes-things";
const FAMILIES = ["read", "static", "proxy", "php", "nodejs", "python", "database", "certificate", "template", "user", "cloudflare", "panel", "master-credentials"];
const DEFAULT_FAMILIES = ["read", "static", "proxy", "php", "nodejs", "database", "certificate", "template", "user"];

if (flag("--help") || argv.length === 0) {
  process.stdout.write(`usage: contract-test.mjs ${CONFIRM} (--ssh-host ALIAS | --local) --file-dir DIR [options]
       contract-test.mjs --plan (--ssh-host ALIAS | --local) --file-dir DIR [options]   (prints the plan, touches nothing)
  --only a,b            families to run: ${FAMILIES.join(", ")} (default: ${DEFAULT_FAMILIES.join(", ")})
  --include-panel       also: panel Basic Auth on then off, release channel set to its current value is NOT touched
  --elevation none      the account is root (default: sudo)
  --clpctl-path PATH    default /usr/bin/clpctl
  --domain-suffix S     default example.invalid
  --php 8.3 --node 20 --python 3.12   runtime versions to use
  --node-port 39401 --python-port 39402   app ports (39400-39409); pick another when the server says a port is in use
  --report FILE         write the report (markdown) to FILE
`);
  process.exit(argv.length === 0 ? 2 : 0);
}

const planOnly = flag("--plan");
if (!planOnly && !flag(CONFIRM)) {
  process.stderr.write(`refusing to run: pass ${CONFIRM} (this creates and deletes things on the server), or --plan to see what it would do\n`);
  process.exit(2);
}
const sshHost = value("--ssh-host");
const local = flag("--local");
const fileDir = value("--file-dir");
if (sshHost === undefined && !local) {
  process.stderr.write("give --ssh-host ALIAS or --local\n");
  process.exit(2);
}
if (sshHost !== undefined && local) {
  process.stderr.write("give only one of --ssh-host and --local\n");
  process.exit(2);
}
// the alias goes to ssh as an argument and into a generated configuration: a plain host name or alias only
if (sshHost !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$/.test(sshHost)) {
  process.stderr.write("--ssh-host must be a plain host name or ssh alias (letters, digits, . _ : -)\n");
  process.exit(2);
}
if (fileDir === undefined || !/^\/[A-Za-z0-9._/-]{3,200}$/.test(fileDir)) {
  process.stderr.write("--file-dir must be an absolute path of safe characters\n");
  process.exit(2);
}
const only = (value("--only", DEFAULT_FAMILIES.join(",")) ?? "").split(",").filter(Boolean);
for (const f of only) if (!FAMILIES.includes(f)) {
  process.stderr.write(`unknown family ${f}\n`);
  process.exit(2);
}
if (flag("--include-panel") && !only.includes("panel")) only.push("panel");

const suffix = value("--domain-suffix", "example.invalid");
const rand = randomBytes(3).toString("hex");
const names = {
  domain: (kind) => `mcp-test-${kind}-${rand}.${suffix}`,
  siteUser: (kind) => `mcpt${kind.slice(0, 3)}${rand}`,
  database: `mcptdata${rand}`,
  dbUser: `mcptu${rand}`,
  template: `MCP Test ${rand}`,
  panelUser: `mcptpanel${rand}`,
  basicAuthUser: `mcptauth${rand}`,
};
const ports = { nodejs: Number(value("--node-port", "39401")), python: Number(value("--python-port", "39402")) };
for (const [kind, port] of Object.entries(ports)) if (!Number.isInteger(port) || port < 39400 || port > 39409) {
  process.stderr.write(`--${kind === "nodejs" ? "node" : kind}-port must be from 39400 to 39409\n`);
  process.exit(2);
}
const versions = { php: value("--php", "8.3"), nodejs: value("--node", "20"), python: value("--python", "3.12") };

const STEPS = {
  read: ["clp_server_info", "clp_list_commands", "clp_user_list", "clp_vhost_templates_list", "clp_vhost_template_view (Generic)"],
  static: [`clp_site_add_static ${names.domain("static")}`, "clp_site_delete (same site)"],
  proxy: [`clp_site_add_reverse_proxy ${names.domain("proxy")} -> http://127.0.0.1:39400`, "clp_site_delete (same site)"],
  php: [`clp_site_add_php ${names.domain("php")} (PHP ${versions.php}, template Generic)`, "clp_site_delete (same site)"],
  nodejs: [`clp_site_add_nodejs ${names.domain("nodejs")} (Node ${versions.nodejs}, port ${ports.nodejs})`, "clp_site_delete (same site)"],
  python: [`clp_site_add_python ${names.domain("python")} (Python ${versions.python}, port ${ports.python})`, "clp_site_delete (same site)"],
  database: [`a static site ${names.domain("db")}`, `clp_db_add ${names.database} (user ${names.dbUser})`, "clp_db_export to --file-dir/dumps, clp_db_import into the same database", "clp_db_delete, then clp_db_add under the same name (it must be free again)", "clp_site_delete (the site)"],
  certificate: [`a static site ${names.domain("cert")}`, "a self-signed certificate generated here and copied into --file-dir/certs", "clp_site_install_certificate", "clp_site_delete (the site)"],
  template: [`clp_vhost_template_add "${names.template}" from a file in --file-dir/templates`, "clp_vhost_template_view", "clp_vhost_template_delete"],
  user: [`clp_user_add ${names.panelUser} (role user, one throwaway site)`, "clp_user_list shows it", "clp_user_reset_password, clp_user_disable_mfa", "clp_user_delete"],
  cloudflare: ["clp_cloudflare_update_ips", "clp_vhost_templates_import (both contact the internet)"],
  panel: [`clp_cloudpanel_enable_basic_auth ${names.basicAuthUser}`, "clp_cloudpanel_disable_basic_auth (within seconds)"],
  "master-credentials": ["clp_db_show_master_credentials (the output is saved to a local file, never shown)"],
};

if (planOnly) {
  process.stdout.write(`PLAN (nothing is contacted)\nserver: ${local ? "local" : `ssh ${sshHost}`}   file directory: ${fileDir}\n`);
  for (const f of only) process.stdout.write(`\n[${f}]\n${STEPS[f].map((s) => `  - ${s}`).join("\n")}\n`);
  process.stdout.write(`\nFiles go below ${fileDir}/dumps, ${fileDir}/certs and ${fileDir}/templates (created if missing, mode 700).\n`);
  process.stdout.write("Everything created is deleted at the end, also after a failure or an interrupt.\n");
  process.exit(0);
}

const { Client } = await import("@modelcontextprotocol/client");
const { StdioClientTransport } = await import("@modelcontextprotocol/client/stdio");
const dist = join(ROOT, "dist", "index.js");
if (!existsSync(dist)) {
  process.stderr.write("run npm run build first\n");
  process.exit(2);
}

const work = mkdtempSync(join(tmpdir(), "clp-contract-"));
const stateDir = join(work, "state");
const configPath = join(work, "config.json");
writeFileSync(configPath, JSON.stringify({
  profiles: {
    contract: {
      ...(local ? { local: true } : { ssh: { host: sshHost } }),
      elevation: value("--elevation", "sudo"),
      clpctlPath: value("--clpctl-path", "/usr/bin/clpctl"),
      allow: ["write", "destructive", "admin"],
      fileDirs: [fileDir],
      allowUntrustedFileDirs: true, // a throw-away directory, often under a home directory or /tmp
      appPorts: ["39400-39409"], // the throwaway upstream/app ports below
      rateLimits: { write: [1000, 1], destructive: [1000, 1], admin: [1000, 1], ask: [1000, 1] },
      timeoutsSeconds: { default: 180, letsEncrypt: 600, db: 600 },
    },
  },
}));
chmodSync(configPath, 0o600);

const created = { sites: [], panelUsers: [], templates: [], files: [], dirs: [], basicAuth: false };
const SUBDIRS = ["dumps", "certs", "templates"];
const report = [];
let failures = 0;

const client = new Client({ name: "contract-test", version: "0.0.0" }, { capabilities: { elicitation: { form: {} } } });
client.setRequestHandler("elicitation/create", async (request) => {
  const props = request.params.requestedSchema?.properties ?? {};
  if (props.approve !== undefined) return { action: "accept", content: { approve: true } };
  const m = /exactly: (.+)$/m.exec(request.params.message ?? "");
  const target = m?.[1]?.trim() ?? "";
  const mine = [...created.sites, ...created.panelUsers, ...created.templates, names.panelUser, names.template, names.database, names.basicAuthUser, "disable-basic-auth", "show-master-credentials"];
  if (target !== "" && mine.includes(target)) return { action: "accept", content: { typed: target } };
  report.push(`REFUSED to approve a target that is not one of this run's throwaway names: ${target.slice(0, 60)}`);
  return { action: "decline" };
});
await client.connect(new StdioClientTransport({
  command: process.execPath,
  args: [dist],
  env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? work, CLOUDPANEL_MCP_CONFIG: configPath, CLOUDPANEL_MCP_STATE_DIR: stateDir, ...(process.env.CLPCTL_SIM_STATE ? { CLPCTL_SIM_STATE: process.env.CLPCTL_SIM_STATE } : {}) },
  stderr: "pipe",
}));

async function call(tool, args = {}) {
  const result = await client.callTool({ name: tool, arguments: args }, { timeout: 15 * 60_000 });
  const text = result.content?.[0]?.text ?? "{}";
  let body;
  try { body = JSON.parse(text); } catch { body = { ok: false, raw: text.slice(0, 300) }; }
  return { isError: result.isError === true, body };
}

async function apply(tool, args = {}) {
  const plan = await call(tool, { ...args, dryRun: true });
  if (plan.isError || typeof plan.body.planToken !== "string") return plan;
  return call(tool, { ...args, planToken: plan.body.planToken });
}

function check(label, ok, detail = "") {
  if (!ok) failures += 1;
  const line = `${ok ? "PASS" : "FAIL"}  ${label}${detail ? `  [${detail}]` : ""}`;
  report.push(line);
  process.stdout.write(`${line}\n`);
}

const brief = (r) => `exit ${r.body.exitCode ?? "-"}${r.body.error ? `, ${String(r.body.error).slice(0, 100)}` : ""}${r.body.output?.serverMessage ? `, server: ${String(r.body.output.serverMessage).slice(0, 100)}` : ""}${r.body.reason ? `, ${String(r.body.reason).slice(0, 100)}` : ""}${r.isError && !r.body.output?.serverMessage && r.body.output ? `, stdout: ${String(r.body.output.stdout ?? "").replace(/\s+/g, " ").slice(0, 200)}, stderr: ${String(r.body.output.stderr ?? "").replace(/\s+/g, " ").slice(0, 200)}` : ""}`;

async function step(label, fn) {
  process.stdout.write(`\n# ${label}\n`);
  try { await fn(); } catch (error) { check(`${label} (threw)`, false, String(error?.message ?? error).slice(0, 160)); }
}

const ssh = (command, input) =>
  spawnSync("ssh", ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", sshHost, "--", command], { input, encoding: "utf8" });

/** Creates --file-dir and its subdirectories that are missing (mode 700) and remembers which it made. */
function prepareDirs() {
  const wanted = [fileDir, ...SUBDIRS.map((d) => `${fileDir}/${d}`)];
  if (local) {
    for (const dir of wanted) {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: dirMode(dir) });
        chmodSync(dir, dirMode(dir));
        created.dirs.push(dir);
      }
    }
    return;
  }
  // one remote command: report each directory this run had to create
  const script = wanted.map((d) => `if [ ! -d '${d}' ]; then (umask 022; mkdir -p -m ${dirMode(d).toString(8)} -- '${d}') && echo 'made:${d}'; fi`).join("; ");
  const r = ssh(script);
  if (r.status !== 0) throw new Error(`could not prepare ${fileDir}: ${r.stderr.slice(0, 100)}`);
  for (const line of r.stdout.split("\n")) if (line.startsWith("made:")) created.dirs.push(line.slice(5));
}

/** The base directory and templates/ must be readable by the account clpctl reads templates as (not root); dumps/ and certs/ stay private. */
function dirMode(dir) {
  return dir === fileDir || dir.endsWith("/templates") ? 0o755 : 0o700;
}

async function putFile(path, text, readable = false) {
  if (local) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text, { mode: readable ? 0o644 : 0o600 });
    chmodSync(path, readable ? 0o644 : 0o600);
  } else {
    const r = ssh(`umask ${readable ? "022" : "077"}; cat > '${path}'`, text);
    if (r.status !== 0) throw new Error(`could not write ${path}: ${r.stderr.slice(0, 100)}`);
  }
  created.files.push(path);
}

async function addSite(kind, tool, extra) {
  const domain = names.domain(kind);
  const r = await apply(tool, { domainName: domain, siteUser: names.siteUser(kind), ...extra });
  check(`${tool}`, !r.isError, brief(r));
  if (!r.isError) created.sites.push(domain);
  return { domain, r };
}

async function deleteSite(domain) {
  const r = await apply("clp_site_delete", { domainName: domain });
  check(`clp_site_delete ${domain}`, !r.isError, brief(r));
  if (!r.isError) created.sites = created.sites.filter((d) => d !== domain);
}

const run = {
  async read() {
    const info = await call("clp_server_info");
    check("clp_server_info", !info.isError && info.body.detection?.status === "ok", `detection ${info.body.detection?.status}, ${info.body.detection?.commandCount} commands`);
    const cmds = await call("clp_list_commands");
    check("clp_list_commands: no documented command missing", !cmds.isError && (cmds.body.documentedCommandsMissingOnServer ?? []).length === 0, `missing ${JSON.stringify(cmds.body.documentedCommandsMissingOnServer)}; without a tool ${JSON.stringify((cmds.body.commandsOnServerWithoutATool ?? []).map((c) => c.command))}; option differences ${JSON.stringify((cmds.body.optionDifferences ?? []).map((d) => d.command))}`);
    const users = await call("clp_user_list");
    check("clp_user_list parses a table", !users.isError && (users.body.output?.table?.rows?.length ?? 0) > 0, `${users.body.output?.table?.rows?.length} rows`);
    const tpl = await call("clp_vhost_templates_list");
    check("clp_vhost_templates_list has Generic", !tpl.isError && (tpl.body.output?.table?.rows ?? []).some((r) => r[0] === "Generic"));
    const view = await call("clp_vhost_template_view", { name: "Generic" });
    check("clp_vhost_template_view Generic", !view.isError && /server/.test(view.body.output?.stdout ?? ""), brief(view));
  },
  async static() {
    const { domain } = await addSite("static", "clp_site_add_static", {});
    const password = created.sites.includes(domain);
    if (password) await deleteSite(domain);
  },
  async proxy() {
    const { domain } = await addSite("proxy", "clp_site_add_reverse_proxy", { reverseProxyUrl: "http://127.0.0.1:39400" });
    if (created.sites.includes(domain)) await deleteSite(domain);
  },
  async php() {
    const { domain } = await addSite("php", "clp_site_add_php", { phpVersion: versions.php, vhostTemplate: "Generic" });
    if (created.sites.includes(domain)) await deleteSite(domain);
  },
  async nodejs() {
    const { domain } = await addSite("nodejs", "clp_site_add_nodejs", { nodejsVersion: versions.nodejs, appPort: ports.nodejs });
    if (created.sites.includes(domain)) await deleteSite(domain);
  },
  async python() {
    const { domain } = await addSite("python", "clp_site_add_python", { pythonVersion: versions.python, appPort: ports.python });
    if (created.sites.includes(domain)) await deleteSite(domain);
  },
  async database() {
    const { domain } = await addSite("db", "clp_site_add_static", {});
    if (!created.sites.includes(domain)) return;
    const add = await apply("clp_db_add", { domainName: domain, databaseName: names.database, databaseUserName: names.dbUser });
    check("clp_db_add", !add.isError, brief(add));
    const dump = `${fileDir}/dumps/mcpt-${rand}.sql`;
    if (!add.isError) {
      const exp = await apply("clp_db_export", { databaseName: names.database, file: dump });
      check("clp_db_export (absolute path)", !exp.isError, brief(exp));
      created.files.push(dump);
      if (!exp.isError) {
        const imp = await apply("clp_db_import", { databaseName: names.database, file: dump });
        check("clp_db_import (absolute path)", !imp.isError, brief(imp));
      }
      const del = await apply("clp_db_delete", { databaseName: names.database });
      check("clp_db_delete", !del.isError, brief(del));
      // the effect, not only the exit status: the name is free again. The first database user is left behind by
      // db:delete, so another one is used; the site's deletion below removes this database too.
      const again = await apply("clp_db_add", { domainName: domain, databaseName: names.database, databaseUserName: `${names.dbUser}b` });
      check("the database is gone: its name can be used again", !again.isError, brief(again));
    }
    await deleteSite(domain);
  },
  async certificate() {
    const { domain } = await addSite("cert", "clp_site_add_static", {});
    if (!created.sites.includes(domain)) return;
    const dir = mkdtempSync(join(tmpdir(), "clp-cert-"));
    const gen = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", join(dir, "k.key"), "-out", join(dir, "c.crt"), "-days", "2", "-subj", `/CN=${domain}`], { encoding: "utf8" });
    check("self-signed certificate generated locally", gen.status === 0, gen.stderr.slice(0, 80));
    if (gen.status === 0) {
      const key = `${fileDir}/certs/mcpt-${rand}.key`;
      const crt = `${fileDir}/certs/mcpt-${rand}.crt`;
      await putFile(key, readFileSync(join(dir, "k.key"), "utf8"));
      await putFile(crt, readFileSync(join(dir, "c.crt"), "utf8"));
      const r = await apply("clp_site_install_certificate", { domainName: domain, privateKey: key, certificate: crt });
      check("clp_site_install_certificate", !r.isError, brief(r));
    }
    rmSync(dir, { recursive: true, force: true });
    await deleteSite(domain);
  },
  async template() {
    const file = `${fileDir}/templates/mcpt-${rand}.tpl`;
    await putFile(file, '#{"rootDirectory":"public","phpVersion":"8.3"}\nserver {\n  listen 80;\n  {{server_name}}\n  {{root}}\n}\n', true);
    const add = await apply("clp_vhost_template_add", { name: names.template, file });
    check("clp_vhost_template_add", !add.isError, brief(add));
    if (!add.isError) {
      created.templates.push(names.template);
      const view = await call("clp_vhost_template_view", { name: names.template });
      check("clp_vhost_template_view of the new template", !view.isError && /server/.test(view.body.output?.stdout ?? ""));
      const list = await call("clp_vhost_templates_list");
      check("the template is listed", (list.body.output?.table?.rows ?? []).some((r) => r[0] === names.template));
      const del = await apply("clp_vhost_template_delete", { name: names.template });
      check("clp_vhost_template_delete", !del.isError, brief(del));
      if (!del.isError) created.templates = created.templates.filter((t) => t !== names.template);
    }
  },
  async user() {
    const { domain } = await addSite("usr", "clp_site_add_static", {});
    const add = await apply("clp_user_add", { userName: names.panelUser, email: `${names.panelUser}@example.com`, firstName: "Contract", lastName: "Test", role: "user", sites: created.sites.includes(domain) ? [domain] : undefined, timezone: "UTC", status: "1" });
    check("clp_user_add", !add.isError, brief(add));
    if (!add.isError) {
      created.panelUsers.push(names.panelUser);
      const list = await call("clp_user_list");
      check("the new user is listed", (list.body.output?.table?.rows ?? []).some((r) => r[0] === names.panelUser));
      const reset = await apply("clp_user_reset_password", { userName: names.panelUser });
      check("clp_user_reset_password", !reset.isError, brief(reset));
      const mfa = await apply("clp_user_disable_mfa", { userName: names.panelUser });
      check("clp_user_disable_mfa", !mfa.isError, brief(mfa));
      const del = await apply("clp_user_delete", { userName: names.panelUser });
      check("clp_user_delete", !del.isError, brief(del));
      if (!del.isError) created.panelUsers = created.panelUsers.filter((u) => u !== names.panelUser);
    }
    if (created.sites.includes(domain)) await deleteSite(domain);
  },
  async cloudflare() {
    const ips = await apply("clp_cloudflare_update_ips");
    check("clp_cloudflare_update_ips", !ips.isError, brief(ips));
    const imp = await apply("clp_vhost_templates_import");
    check("clp_vhost_templates_import", !imp.isError, brief(imp));
  },
  async panel() {
    const on = await apply("clp_cloudpanel_enable_basic_auth", { userName: names.basicAuthUser });
    check("clp_cloudpanel_enable_basic_auth", !on.isError, brief(on));
    if (!on.isError) created.basicAuth = true;
    const off = await apply("clp_cloudpanel_disable_basic_auth");
    check("clp_cloudpanel_disable_basic_auth", !off.isError, brief(off));
    if (!off.isError) created.basicAuth = false;
  },
  async "master-credentials"() {
    const r = await apply("clp_db_show_master_credentials");
    check("clp_db_show_master_credentials saves to a file and shows nothing", !r.isError && typeof r.body.secretsFile === "string" && !/pass/i.test(JSON.stringify(r.body.output ?? {})), brief(r));
  },
};

async function cleanup() {
  process.stdout.write("\n# cleanup\n");
  if (created.basicAuth) await apply("clp_cloudpanel_disable_basic_auth").catch(() => undefined);
  for (const user of [...created.panelUsers]) await apply("clp_user_delete", { userName: user }).catch(() => undefined);
  for (const template of [...created.templates]) await apply("clp_vhost_template_delete", { name: template }).catch(() => undefined);
  for (const domain of [...created.sites]) await apply("clp_site_delete", { domainName: domain }).catch(() => undefined);
  const left = await call("clp_user_list").catch(() => undefined);
  const leftover = (left?.body.output?.table?.rows ?? []).filter((r) => String(r[0]).startsWith("mcpt"));
  check("no throwaway panel user is left", leftover.length === 0, JSON.stringify(leftover.map((r) => r[0])));
  const tpl = await call("clp_vhost_templates_list").catch(() => undefined);
  check("no throwaway template is left", !(tpl?.body.output?.table?.rows ?? []).some((r) => String(r[0]).startsWith("MCP Test")));
  if (created.files.length > 0) {
    // only files this run created, by exact path; the directory belongs to the ssh account, so it may delete them
    let removed = false;
    if (local) {
      for (const f of created.files) rmSync(f, { force: true });
      removed = true;
    } else {
      removed = ssh(`rm -f -- ${created.files.map((f) => `'${f}'`).join(" ")}`).status === 0;
    }
    check("the files this run put in the file directory are removed", removed, removed ? created.files.length + " files" : `remove them yourself: ${created.files.join(" ")}`);
  }
  if (created.dirs.length > 0) {
    // the directories this run made, deepest first; rmdir only removes an empty one
    const dirs = [...created.dirs].reverse();
    let ok = true;
    if (local) {
      for (const d of dirs) { try { rmdirSync(d); } catch { ok = false; } }
    } else {
      ok = ssh(`rmdir -- ${dirs.map((d) => `'${d}'`).join(" ")}`).status === 0;
    }
    check("the directories this run made are removed", ok, ok ? `${dirs.length} directories` : `remove them yourself if empty: ${dirs.join(" ")}`);
  }
}

let interrupted = false;
process.on("SIGINT", () => { interrupted = true; });
const startedAt = new Date().toISOString();
try {
  if (only.some((f) => ["database", "certificate", "template"].includes(f))) prepareDirs();
  for (const family of only) {
    if (interrupted) break;
    await step(`${family}: ${STEPS[family].join("; ")}`, run[family]);
  }
} finally {
  await cleanup().catch((e) => process.stdout.write(`cleanup problem: ${e}\n`));
  await client.close().catch(() => undefined);
  const out = value("--report");
  const text = `# Contract test ${startedAt}\n\nserver: ${local ? "local" : `ssh ${sshHost}`}; families: ${only.join(", ")}; secrets and audit log of this run: ${work} (delete it)\n\n${report.map((l) => `- ${l}`).join("\n")}\n`;
  if (out) writeFileSync(out, text);
  process.stdout.write(`\n${failures === 0 ? "ALL PASSED" : `${failures} FAILED`}\n`);
  process.exitCode = failures === 0 ? 0 : 1;
}
