/**
 * A strict stand-in for CloudPanel's `clpctl`, for tests. Its grammar comes from the official
 * documentation (docs/COMMAND-REFERENCE.md) and from the real output recorded on CloudPanel
 * 2.5.4 (test/fixtures/recorded). It refuses anything it does not know: an unknown
 * command, an unknown option, a missing required option, a positional argument, a value that does
 * not look like "--name=value". State (sites, users, databases, templates, certificates) is a plain
 * object so that several invocations can share it through a JSON file.
 */
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "fixtures", "recorded");

export interface SimSite { domain: string; type: string; siteUser: string; password: string; version?: string; port?: number; proxy?: string; template?: string; cert?: string }
export interface SimDb { name: string; user: string; domain: string; password: string }
export interface SimUser { userName: string; email: string; firstName: string; lastName: string; role: string; status: string; sites?: string; timezone: string; password: string; mfa: boolean }
export interface SimTemplate { name: string; rootDirectory: string; type: string; content: string }

export interface SimState {
  sites: SimSite[];
  dbs: SimDb[];
  /** database users that outlive their database (observed: db:delete leaves the user) */
  orphanDbUsers: string[];
  users: SimUser[];
  templates: SimTemplate[];
  basicAuth: { userName: string; password: string } | null;
  channel: string;
  installed: { php: string[]; node: string[]; python: string[] };
  purges: string[];
}

export interface SimResult { exitCode: number; stdout: string; stderr: string }

export interface SimOptions {
  /** Exit status of an error. Real CloudPanel's is unknown; tests try 1 and 0. */
  errorExitCode?: number;
  /** The user the process runs as: "root" or a site user (site-user commands need the latter). */
  runAs?: string;
}

const DOMAIN = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/;

function parseTemplates(): SimTemplate[] {
  const text = readFileSync(join(FIXTURES, "vhost-templates-list.txt"), "utf8");
  return text
    .split("\n")
    .filter((l) => l.startsWith("|"))
    .slice(1)
    .map((l) => {
      const [name = "", rootDirectory = "", type = ""] = l.slice(1, -1).split("|").map((c) => c.trim());
      return { name, rootDirectory, type, content: `server {\n  # ${name}\n  {{server_name}}\n  {{root}}\n}\n` };
    });
}

export function initialState(): SimState {
  return {
    sites: [],
    dbs: [],
    orphanDbUsers: [],
    users: [
      { userName: "admin", email: "admin@example.com", firstName: "Alex", lastName: "Example", role: "admin", status: "1", timezone: "UTC", password: "x", mfa: true },
    ],
    templates: parseTemplates(),
    basicAuth: null,
    channel: "stable",
    installed: { php: ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"], node: ["12", "14", "16", "18", "20", "22", "24"], python: ["3.12"] },
    purges: [],
  };
}

export function loadState(path: string): SimState {
  return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as SimState) : initialState();
}

export function saveState(path: string, state: SimState): void {
  writeFileSync(path, JSON.stringify(state, null, 2));
}

function renderTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
  const border = `+${widths.map((w) => "-".repeat(w + 2)).join("+")}+`;
  const line = (cells: string[]): string => `|${cells.map((c, i) => ` ${c.padEnd(widths[i] ?? 0)} `).join("|")}|`;
  return [border, line(headers), border, ...rows.map(line), border].join("\n") + "\n";
}

class Fail extends Error {}

interface OptDef { required: boolean; check?: (value: string, st: SimState) => string | null }
interface CmdDef {
  opts: Record<string, OptDef>;
  flags?: string[];
  siteUserCommand?: boolean;
  run: (o: Record<string, string>, flags: Set<string>, st: SimState, ctx: { runAs: string }) => { stdout?: string; stderr?: string };
}

const invalid = (field: string): string => `${field}: This value is not valid.`;
const re = (field: string, pattern: RegExp) => (v: string): string | null => (pattern.test(v) ? null : invalid(field));
const oneOf = (field: string, values: string[]) => (v: string): string | null => (values.includes(v) ? null : invalid(field));

const domainCheck: OptDef = { required: true, check: re("domainName", DOMAIN) };
const siteUserCheck: OptDef = {
  required: true,
  check: (v, st) =>
    !/^[a-z][a-z0-9_-]{0,31}$/.test(v) ? invalid("siteUser") : st.sites.some((s) => s.siteUser === v) || ["root", "clp", "admin"].includes(v) ? "siteUser: This value already exists." : null,
};
const passwordCheck = (field: string): OptDef => ({ required: true, check: (v) => (v.length >= 8 ? null : `${field}: This value is too short. It should have 8 characters or more.`) });
const portCheck: OptDef = { required: true, check: (v) => (/^[0-9]{1,5}$/.test(v) && Number(v) >= 1 && Number(v) <= 65535 ? null : invalid("appPort")) };

function addSite(type: string, extra: (o: Record<string, string>, st: SimState) => Partial<SimSite>): CmdDef["run"] {
  return (o, _f, st) => {
    const domain = o["domainName"] as string;
    if (st.sites.some((s) => s.domain === domain || s.domain === `www.${domain}` || `www.${s.domain}` === domain)) {
      throw new Fail("domainName: This value already exists.");
    }
    st.sites.push({ domain, type, siteUser: o["siteUser"] as string, password: o["siteUserPassword"] as string, ...extra(o, st) });
    return { stdout: `The ${type} site ${domain} has been created.\n` };
  };
}

function requireSite(st: SimState, domain: string): SimSite {
  const site = st.sites.find((s) => s.domain === domain);
  if (site === undefined) throw new Fail("domainName: The site does not exist.");
  return site;
}

function requireFile(path: string, field: string): void {
  if (!existsSync(path) || !statSync(path).isFile()) throw new Fail(`${field}: The file does not exist.`);
}

const COMMANDS: Record<string, CmdDef> = {
  "cloudflare:update:ips": { opts: {}, run: () => ({ stdout: "Cloudflare IPs updated.\n" }) },
  "cloudpanel:enable:basic-auth": {
    opts: { userName: { required: true, check: re("userName", /^[A-Za-z0-9][A-Za-z0-9._-]*$/) }, password: passwordCheck("password") },
    run: (o, _f, st) => { st.basicAuth = { userName: o["userName"] as string, password: o["password"] as string }; return { stdout: "Basic auth enabled.\n" }; },
  },
  "cloudpanel:disable:basic-auth": { opts: {}, run: (_o, _f, st) => { st.basicAuth = null; return { stdout: "Basic auth disabled.\n" }; } },
  "cloudpanel:set:release-channel": {
    opts: { channel: { required: true, check: oneOf("channel", ["stable", "test"]) } },
    run: (o, _f, st) => { st.channel = o["channel"] as string; return { stdout: `Release channel set to ${st.channel}.\n` }; },
  },
  "db:show:master-credentials": {
    opts: {},
    run: () => ({
      stdout: renderTable(["Host", "User Name", "Password", "Port"], [["127.0.0.1", "root", "SIM-MASTER-PASSWORD-0123456789", "3306"]]) +
        "Connect Command: mysql -u root -pSIM-MASTER-PASSWORD-0123456789 -h 127.0.0.1 -P 3306\n",
    }),
  },
  "db:add": {
    opts: {
      domainName: domainCheck,
      databaseName: { required: true, check: re("databaseName", /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/) },
      databaseUserName: { required: true, check: re("databaseUserName", /^[A-Za-z0-9_]{1,64}$/) },
      databaseUserPassword: passwordCheck("databaseUserPassword"),
    },
    run: (o, _f, st) => {
      requireSite(st, o["domainName"] as string);
      if (st.dbs.some((d) => d.name === o["databaseName"])) throw new Fail("databaseName: This value already exists.");
      if (st.dbs.some((d) => d.user === o["databaseUserName"]) || st.orphanDbUsers.includes(o["databaseUserName"] as string)) {
        throw new Fail("databaseUserName: This value already exists.");
      }
      st.dbs.push({ name: o["databaseName"] as string, user: o["databaseUserName"] as string, domain: o["domainName"] as string, password: o["databaseUserPassword"] as string });
      return { stdout: `The database ${o["databaseName"]} has been added.\n` };
    },
  },
  "db:delete": {
    opts: { databaseName: { required: true, check: re("databaseName", /^[A-Za-z0-9][A-Za-z0-9-]*$/) } },
    run: (o, _f, st) => {
      const db = st.dbs.find((d) => d.name === o["databaseName"]);
      if (db === undefined) throw new Fail("databaseName: The database does not exist.");
      st.dbs = st.dbs.filter((d) => d !== db);
      st.orphanDbUsers.push(db.user);
      return { stderr: `Confirm to delete the database: ${db.name} (yes/no): `, stdout: `The database ${db.name} has been deleted.\n` };
    },
  },
  "db:export": {
    opts: { databaseName: { required: true }, file: { required: true } },
    run: (o, _f, st) => {
      if (!st.dbs.some((d) => d.name === o["databaseName"])) throw new Fail("databaseName: The database does not exist.");
      writeFileSync(o["file"] as string, `-- dump of ${o["databaseName"]}\n`);
      return { stdout: `The database ${o["databaseName"]} has been exported.\n` };
    },
  },
  "db:import": {
    opts: { databaseName: { required: true }, file: { required: true } },
    run: (o, _f, st) => {
      if (!st.dbs.some((d) => d.name === o["databaseName"])) throw new Fail("databaseName: The database does not exist.");
      requireFile(o["file"] as string, "file");
      return { stdout: `The dump has been imported into ${o["databaseName"]}.\n` };
    },
  },
  "lets-encrypt:install:certificate": {
    opts: { domainName: domainCheck, subjectAlternativeName: { required: false, check: (v) => (v.split(",").every((d) => DOMAIN.test(d)) ? null : invalid("subjectAlternativeName")) } },
    run: (o, _f, st) => { requireSite(st, o["domainName"] as string).cert = "letsencrypt"; return { stdout: "Certificate installed.\n" }; },
  },
  "site:add:nodejs": {
    opts: { domainName: domainCheck, nodejsVersion: { required: true, check: (v, st) => (st.installed.node.includes(v) ? null : invalid("nodejsVersion")) }, appPort: portCheck, siteUser: siteUserCheck, siteUserPassword: passwordCheck("siteUserPassword") },
    run: addSite("nodejs", (o) => ({ version: o["nodejsVersion"] as string, port: Number(o["appPort"]) })),
  },
  "site:add:static": { opts: { domainName: domainCheck, siteUser: siteUserCheck, siteUserPassword: passwordCheck("siteUserPassword") }, run: addSite("static", () => ({})) },
  "site:add:php": {
    opts: {
      domainName: domainCheck,
      phpVersion: { required: true, check: (v, st) => (st.installed.php.includes(v) ? null : invalid("phpVersion")) },
      vhostTemplate: { required: true, check: (v, st) => (st.templates.some((t) => t.name === v) ? null : invalid("vhostTemplate")) },
      siteUser: siteUserCheck,
      siteUserPassword: passwordCheck("siteUserPassword"),
    },
    run: addSite("php", (o) => ({ version: o["phpVersion"] as string, template: o["vhostTemplate"] as string })),
  },
  "site:add:python": {
    opts: { domainName: domainCheck, pythonVersion: { required: true, check: (v, st) => (st.installed.python.includes(v) ? null : invalid("pythonVersion")) }, appPort: portCheck, siteUser: siteUserCheck, siteUserPassword: passwordCheck("siteUserPassword") },
    run: addSite("python", (o) => ({ version: o["pythonVersion"] as string, port: Number(o["appPort"]) })),
  },
  "site:add:reverse-proxy": {
    opts: { domainName: domainCheck, reverseProxyUrl: { required: true, check: re("reverseProxyUrl", /^https?:\/\/[^\s]+$/) }, siteUser: siteUserCheck, siteUserPassword: passwordCheck("siteUserPassword") },
    run: addSite("reverse-proxy", (o) => ({ proxy: o["reverseProxyUrl"] as string })),
  },
  "site:install:certificate": {
    opts: { domainName: domainCheck, privateKey: { required: true }, certificate: { required: true }, certificateChain: { required: false } },
    run: (o, _f, st) => {
      const site = requireSite(st, o["domainName"] as string);
      requireFile(o["privateKey"] as string, "privateKey");
      requireFile(o["certificate"] as string, "certificate");
      if (o["certificateChain"] !== undefined) requireFile(o["certificateChain"], "certificateChain");
      site.cert = "custom";
      return { stdout: "Certificate installed.\n" };
    },
  },
  "site:delete": {
    opts: { domainName: domainCheck },
    flags: ["force"],
    run: (o, f, st) => {
      const site = requireSite(st, o["domainName"] as string);
      if (!f.has("force")) return { stderr: `Are you sure you want to delete ${site.domain}? (yes/no) `, stdout: "Aborted.\n" , ...{ abort: true } } as never;
      st.sites = st.sites.filter((s) => s !== site);
      const gone = st.dbs.filter((d) => d.domain === site.domain);
      st.dbs = st.dbs.filter((d) => d.domain !== site.domain);
      st.orphanDbUsers = st.orphanDbUsers.filter((u) => !gone.some((d) => d.user === u));
      return { stdout: `The site ${site.domain} has been deleted.\n` };
    },
  },
  "system:permissions:reset": {
    siteUserCommand: true,
    opts: { directories: { required: true, check: re("directories", /^[0-7]{3,4}$/) }, files: { required: true, check: re("files", /^[0-7]{3,4}$/) }, path: { required: true } },
    run: (_o, _f, _st, ctx) => {
      if (ctx.runAs === "root") throw new Fail("This command must be run as a site user.");
      return { stdout: "Permissions reset.\n" };
    },
  },
  "user:add": {
    opts: {
      userName: { required: true, check: (v, st) => (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(v) ? invalid("userName") : st.users.some((u) => u.userName === v) ? "userName: This value already exists." : null) },
      email: { required: true, check: re("email", /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/) },
      firstName: { required: true }, lastName: { required: true }, password: passwordCheck("password"),
      role: { required: true, check: oneOf("role", ["admin", "site-manager", "user"]) },
      sites: { required: false }, timezone: { required: true, check: re("timezone", /^[A-Za-z]+(\/[A-Za-z0-9_+-]+)*$/) },
      status: { required: true, check: oneOf("status", ["0", "1"]) },
    },
    run: (o, _f, st) => {
      if (o["sites"] !== undefined && o["role"] !== "user") throw new Fail("sites: Only users with the role user can be restricted to sites.");
      st.users.push({ userName: o["userName"] as string, email: o["email"] as string, firstName: o["firstName"] as string, lastName: o["lastName"] as string, role: o["role"] as string, status: o["status"] as string, ...(o["sites"] === undefined ? {} : { sites: o["sites"] }), timezone: o["timezone"] as string, password: o["password"] as string, mfa: false });
      return { stdout: `The user ${o["userName"]} has been added.\n` };
    },
  },
  "user:delete": {
    opts: { userName: { required: true } },
    flags: ["force"],
    run: (o, f, st) => {
      if (!st.users.some((u) => u.userName === o["userName"])) throw new Fail("userName: The user does not exist.");
      // observed on 2.5.4: without --force it asks, gets no answer (stdin closed), does nothing and exits 0
      if (!f.has("force")) return { stdout: `Confirm to delete the user: ${o["userName"]} (yes/no): ` };
      st.users = st.users.filter((u) => u.userName !== o["userName"]);
      return { stdout: `The user ${o["userName"]} has been deleted.\n` };
    },
  },
  "user:list": {
    opts: {},
    run: (_o, _f, st) => ({
      stdout: renderTable(["User Name", "First Name", "Last Name", "E-Mail", "Role", "Status"], st.users.map((u) => [u.userName, u.firstName, u.lastName, u.email, u.role, u.status === "1" ? "Active" : "Inactive"])),
    }),
  },
  "user:reset:password": {
    opts: { userName: { required: true }, password: passwordCheck("password") },
    run: (o, _f, st) => {
      const user = st.users.find((u) => u.userName === o["userName"]);
      if (user === undefined) throw new Fail("userName: The user does not exist.");
      user.password = o["password"] as string;
      return { stdout: "Password reset.\n" };
    },
  },
  "user:disable:mfa": {
    opts: { userName: { required: true } },
    run: (o, _f, st) => {
      const user = st.users.find((u) => u.userName === o["userName"]);
      if (user === undefined) throw new Fail("userName: The user does not exist.");
      user.mfa = false;
      return { stdout: "Two-factor authentication disabled.\n" };
    },
  },
  "varnish-cache:purge": {
    siteUserCommand: true,
    opts: { purge: { required: true } },
    run: (o, _f, st, ctx) => {
      if (ctx.runAs === "root") throw new Fail("This command must be run as a site user.");
      st.purges.push(o["purge"] as string);
      return { stdout: "Purged.\n" };
    },
  },
  "vhost-templates:import": { opts: {}, run: () => ({ stdout: "Templates imported.\n" }) },
  "vhost-templates:list": {
    opts: {},
    run: (_o, _f, st) => ({ stdout: renderTable(["Name", "Root Directory", "Type"], st.templates.map((t) => [t.name, t.rootDirectory, t.type])) }),
  },
  "vhost-template:add": {
    opts: { name: { required: true }, file: { required: true } },
    run: (o, _f, st) => {
      if (st.templates.some((t) => t.name === o["name"])) throw new Fail("name: This value already exists.");
      requireFile(o["file"] as string, "file");
      st.templates.push({ name: o["name"] as string, rootDirectory: "", type: "Custom", content: readFileSync(o["file"] as string, "utf8") });
      return { stdout: `The template ${o["name"]} has been added.\n` };
    },
  },
  "vhost-template:view": {
    opts: { name: { required: true } },
    run: (o, _f, st) => {
      const t = st.templates.find((x) => x.name === o["name"]);
      if (t === undefined) throw new Fail("name: The template does not exist.");
      return { stdout: t.content };
    },
  },
  "vhost-template:delete": {
    opts: { name: { required: true } },
    run: (o, _f, st) => {
      const t = st.templates.find((x) => x.name === o["name"]);
      if (t === undefined) throw new Fail("name: The template does not exist.");
      if (t.type === "System") throw new Fail("name: A system template cannot be deleted.");
      st.templates = st.templates.filter((x) => x !== t);
      return { stdout: `The template ${t.name} has been deleted.\n` };
    },
  },
};

/** Commands the root listing shows (varnish-cache:purge is not in it on the recorded server). */
export const LISTED_COMMANDS = Object.keys(COMMANDS).filter((c) => c !== "varnish-cache:purge");

export function usageListing(): string {
  return readFileSync(join(FIXTURES, "usage-listing.txt"), "utf8");
}

function errorBlock(message: string, level = "ERROR"): string {
  const line = JSON.stringify({ message, context: [], level: 400, level_name: level, channel: "app", datetime: "2026-01-01T00:00:00+00:00", extra: [] });
  return `${line}\n\n [${level}] ${message}\n\n`;
}

export function describeCommand(name: string): { options: string[]; required: string[]; flags: string[] } | undefined {
  const def = COMMANDS[name];
  if (def === undefined) return undefined;
  return {
    options: Object.keys(def.opts),
    required: Object.entries(def.opts).filter(([, o]) => o.required).map(([n]) => n),
    flags: def.flags ?? [],
  };
}

export class ClpctlSim {
  readonly state: SimState;
  private readonly options: Required<SimOptions>;

  constructor(state: SimState = initialState(), options: SimOptions = {}) {
    this.state = state;
    this.options = { errorExitCode: options.errorExitCode ?? 1, runAs: options.runAs ?? "root" };
  }

  run(argv: readonly string[]): SimResult {
    const [command, ...rest] = argv;
    if (command === undefined) return { exitCode: 0, stdout: usageListing(), stderr: "" };
    const def = COMMANDS[command];
    if (def === undefined) {
      return {
        exitCode: this.options.errorExitCode,
        stdout: errorBlock(`Command "${command}" is not defined.`, "CRITICAL"),
        stderr: "",
      };
    }
    try {
      const values: Record<string, string> = {};
      const flags = new Set<string>();
      for (const arg of rest) {
        const m = /^--([A-Za-z][A-Za-z0-9-]*)(?:=([\s\S]*))?$/.exec(arg);
        if (m === null) throw new Fail(`Too many arguments, expected arguments "".`);
        const [, name = "", value] = m;
        if (value === undefined) {
          if (!(def.flags ?? []).includes(name)) throw new Fail(`The "--${name}" option does not exist.`);
          flags.add(name);
        } else {
          if (def.opts[name] === undefined) throw new Fail(`The "--${name}" option does not exist.`);
          if (name in values) throw new Fail(`The "--${name}" option was given twice.`);
          values[name] = value;
        }
      }
      for (const [name, o] of Object.entries(def.opts)) {
        if (o.required && values[name] === undefined) throw new Fail(`${name}: This value should not be blank.`);
      }
      for (const [name, o] of Object.entries(def.opts)) {
        const v = values[name];
        if (v !== undefined && o.check !== undefined) {
          const problem = o.check(v, this.state);
          if (problem !== null) throw new Fail(problem);
        }
      }
      if (def.siteUserCommand !== true && this.options.runAs !== "root") throw new Fail("This command must be run as root.");
      const out = def.run(values, flags, this.state, { runAs: this.options.runAs }) as { stdout?: string; stderr?: string; abort?: boolean };
      return { exitCode: out.abort === true ? this.options.errorExitCode : 0, stdout: out.stdout ?? "", stderr: out.stderr ?? "" };
    } catch (error) {
      if (error instanceof Fail) return { exitCode: this.options.errorExitCode, stdout: errorBlock(error.message), stderr: "" };
      throw error;
    }
  }
}
