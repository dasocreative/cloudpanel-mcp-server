import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import fc from "fast-check";
import { OUTPUT_PATH, generateGate } from "../scripts/gen-gate.ts";
import { buildCatalog } from "../src/catalog/index.ts";
import type { OptionType } from "../src/catalog/define.ts";
import { renderRemoteCommand } from "../src/exec/quote.ts";
import { isValidOption } from "../src/validate/option-types.ts";
import { RE, SOURCES, type PatternName } from "../src/validate/patterns.ts";
import { HOSTILE } from "./corpus.ts";
import { FIXED_PASSWORD, IS_WINDOWS, makeProfile, shortTmp, writeExecutable } from "./helpers.ts";
import { SAMPLE_ARGS } from "./samples.ts";

const catalog = buildCatalog();
const DIRP = "/var/lib/cloudpanel-mcp-server";
const profile = makeProfile({ siteUserAccess: { shop: { host: "x" } } });
const CTX = { fileDirs: profile.fileDirs, proxyHosts: profile.proxyHosts, appPorts: profile.appPorts };

// every distinct bash we can find (macOS ships 3.2, Homebrew and Linux 5.x)
const BASHES = [...new Set(["/bin/bash", "/opt/homebrew/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"].filter(existsSync).map((p) => realpathSync(p)))];

const text = generateGate();

describe("the generated gate", () => {
  it("is exactly what the generator produces from the catalogue (no drift)", () => {
    assert.equal(readFileSync(OUTPUT_PATH, "utf8"), text);
  });
  it("has no placeholders left and embeds the patterns of the server", () => {
    assert.ok(!text.includes("@@"));
    for (const [name, source] of Object.entries(SOURCES)) assert.ok(text.includes(`RE_${name}='${source}'`), name);
  });
  it("lists every wrapped command and nothing else", () => {
    const inGate = new Set([...text.matchAll(/^ {4}([a-z][a-z:-]+)\) CLASS=/gm)].map((m) => m[1]));
    const inCatalog = new Set(catalog.filter((s) => (s.kind === "clpctl" || s.kind === "siteuser") && s.command !== null).map((s) => s.command));
    assert.deepEqual([...inGate].sort(), [...inCatalog].sort());
  });
  it("declares protected options exactly where a plan names a protected target", () => {
    for (const spec of catalog) {
      if (spec.plan === undefined) continue;
      const plan = spec.plan(SAMPLE_ARGS[spec.name] ?? {}, profile);
      // a site-user tool logs in AS the site user: that user is not an option the gate could see
      const fromPlan = plan.protect.filter((p) => spec.kind === "clpctl" || p.kind !== "siteUser").map((p) => `${p.kind}:${p.value}`).sort();
      // a list option (domains) is protected one entry at a time
      const fromOptions = Object.entries(spec.protectOptions)
        .flatMap(([option, kind]) => String(plan.options.find((o) => o.name === option)?.value).split(",").map((value) => `${kind}:${value}`))
        .sort();
      assert.deepEqual(fromOptions, fromPlan, spec.name);
    }
  });
  for (const bash of BASHES) {
    it(`is valid bash (${bash})`, { skip: IS_WINDOWS }, () => {
      const dir = shortTmp("clpg-");
      const path = join(dir, "gate.sh");
      writeFileSync(path, text);
      const r = spawnSync(bash, ["-n", path], { encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
    });
  }
});

interface GateRig {
  /** The recorder standing in for clpctl: the program word the client must send. */
  readonly clpctl: string;
  /** The recorder standing in for the inventory script. */
  readonly inventory: string;
  run(command: string | undefined, bash?: string, env?: Record<string, string>): { status: number | null; stderr: string; log: string[] };
}

/** A copy of the gate with the program and sudo replaced by recorders, and chosen settings. */
function rig(settings: Record<string, string> = {}, replacements: [string, string][] = []): GateRig {
  const dir = shortTmp("clpg-");
  const log = join(dir, "log");
  const recorder = (marker: string): string =>
    writeExecutable(dir, `rec-${marker.toLowerCase()}`, `#!/bin/sh\nprintf '%s\\0' ${marker} "$@" >> "${log}"\n`);
  let source = text;
  const clpctl = recorder("CLPCTL");
  const all: Record<string, string> = { SUDO: recorder("SUDO"), CLPCTL: clpctl, INVENTORY: recorder("INVENTORY"), SYSLOG: "0", ...settings };
  for (const [name, value] of Object.entries(all)) {
    const pattern = new RegExp(`^${name}=.*$`, "m");
    assert.ok(pattern.test(source), `setting ${name} not found`);
    source = source.replace(pattern, () => `${name}=${value}`);
  }
  for (const [from, to] of replacements) {
    assert.ok(source.includes(from), `${from} not found in the gate`);
    source = source.replace(from, () => to);
  }
  const gate = join(dir, "gate.sh");
  writeFileSync(gate, source);
  return {
    clpctl: all["CLPCTL"] as string,
    inventory: all["INVENTORY"] as string,
    run(command, bash = BASHES[0] as string, extraEnv = {}) {
      const env: Record<string, string> = { PATH: process.env["PATH"] ?? "/usr/bin:/bin", ...extraEnv };
      if (command !== undefined) env["SSH_ORIGINAL_COMMAND"] = command;
      const r = spawnSync(bash, [gate], { env, encoding: "utf8" });
      const logged = existsSync(log) ? readFileSync(log, "utf8").split("\0").slice(0, -1) : [];
      if (existsSync(log)) writeFileSync(log, "");
      return { status: r.status, stderr: r.stderr, log: logged };
    },
  };
}

function commandFor(tool: string, clpctlPath: string, prefix: string[] = ["sudo", "-n"]): { remote: string; command: string; tokens: string[] } {
  const spec = catalog.find((s) => s.name === tool);
  assert.ok(spec?.plan !== undefined, tool);
  const plan = spec.plan(SAMPLE_ARGS[tool] ?? {}, profile);
  const tokens = [
    ...plan.options.map((o) => `--${o.name}=${o.generated !== undefined ? FIXED_PASSWORD : o.value}`),
    ...plan.flags,
  ];
  return { remote: renderRemoteCommand({ prefix, clpctlPath, command: plan.command, tokens }), command: plan.command, tokens };
}

describe("what the gate lets through", { skip: IS_WINDOWS }, () => {
  const all = { ALLOW_WRITE: "1", ALLOW_DESTRUCTIVE: "1", ALLOW_ADMIN: "1" };

  for (const spec of catalog.filter((s) => s.kind === "clpctl" && s.command !== null)) {
    it(`${spec.name}: the exact command the server sends is accepted and forwarded unchanged (sudo and root forms)`, () => {
      const g = rig(all);
      const { remote, command, tokens } = commandFor(spec.name, g.clpctl);
      const viaSudo = g.run(remote);
      assert.equal(viaSudo.status, 0, viaSudo.stderr);
      assert.deepEqual(viaSudo.log, ["SUDO", "-n", g.clpctl, command, ...tokens]);
      const direct = g.run(commandFor(spec.name, g.clpctl, []).remote);
      assert.equal(direct.status, 0, direct.stderr);
      assert.deepEqual(direct.log, ["CLPCTL", command, ...tokens]);
    });
  }

  it("site-user tools are accepted by a site-user gate, without sudo, and refused by a root gate", () => {
    const siteGate = rig({ ...all, SCOPE: "siteuser" });
    const rootGate = rig(all);
    for (const tool of ["clp_system_permissions_reset", "clp_varnish_cache_purge"]) {
      const { remote, command, tokens } = commandFor(tool, siteGate.clpctl, []);
      const ok = siteGate.run(remote);
      assert.equal(ok.status, 0, ok.stderr);
      assert.deepEqual(ok.log, ["CLPCTL", command, ...tokens]);
      assert.equal(rootGate.run(commandFor(tool, rootGate.clpctl, []).remote).status, 126, "a root gate has no site-user commands");
      assert.equal(siteGate.run(commandFor(tool, siteGate.clpctl, ["sudo", "-n"]).remote).status, 126, "no sudo for a site user");
    }
    assert.equal(siteGate.run(commandFor("clp_site_delete", siteGate.clpctl, []).remote).status, 126);
    assert.equal(siteGate.run(siteGate.clpctl).status, 126);
  });

  it("the bare usage listing and the inventory script are accepted only where enabled", () => {
    const g = rig(all);
    assert.deepEqual([g.run(`sudo -n ${g.clpctl}`).status, g.run(g.clpctl).status], [0, 0]);
    assert.equal(g.run(`sudo -n ${g.inventory}`).status, 126, "off by default");
    const inv = rig({ ...all, ALLOW_INVENTORY: "1" });
    assert.equal(inv.run(`sudo -n ${inv.inventory}`).status, 0);
    assert.equal(inv.run(`sudo -n ${inv.inventory} '--x=y'`).status, 126);
    assert.equal(inv.run(`sudo -n ${inv.inventory} x`).status, 126);
    const siteInv = rig({ ...all, ALLOW_INVENTORY: "1", SCOPE: "siteuser" });
    assert.equal(siteInv.run(`sudo -n ${siteInv.inventory}`).status, 126, "never for a site user");
  });
});

describe("class ceilings", { skip: IS_WINDOWS }, () => {
  const classOf = (tool: string): string => (catalog.find((s) => s.name === tool) as { cls: string }).cls;
  const tools = catalog.filter((s) => s.kind === "clpctl" && s.command !== null).map((s) => s.name);
  const settings = (write: string, destructive: string, admin: string) => ({ ALLOW_WRITE: write, ALLOW_DESTRUCTIVE: destructive, ALLOW_ADMIN: admin });

  it("read always; write needs ALLOW_WRITE; destructive and admin need their own switch AND ALLOW_WRITE", () => {
    const cases: [Record<string, string>, (cls: string) => boolean][] = [
      [settings("0", "0", "0"), (c) => c === "read"],
      [settings("1", "0", "0"), (c) => c === "read" || c === "write"],
      [settings("1", "1", "0"), (c) => c !== "admin"],
      [settings("1", "0", "1"), (c) => c !== "destructive"],
      [settings("1", "1", "1"), () => true],
      [settings("0", "1", "1"), (c) => c === "read"],
    ];
    for (const [s, allowed] of cases) {
      const g = rig(s);
      for (const tool of tools) {
        const status = g.run(commandFor(tool, g.clpctl).remote).status;
        assert.equal(status === 0, allowed(classOf(tool)), `${JSON.stringify(s)} ${tool} (${classOf(tool)}) -> ${status}`);
      }
    }
  });

  it("the shipped defaults are read-only plus write, no destructive and no admin", () => {
    const defaults = ["ALLOW_WRITE=1", "ALLOW_DESTRUCTIVE=0", "ALLOW_ADMIN=0", "ALLOW_INVENTORY=0"];
    for (const line of defaults) assert.match(text, new RegExp(`^${line}`, "m"));
    const g = rig();
    assert.equal(g.run(commandFor("clp_site_add_static", g.clpctl).remote).status, 0);
    assert.equal(g.run(commandFor("clp_site_delete", g.clpctl).remote).status, 126);
    assert.equal(g.run(commandFor("clp_user_add", g.clpctl).remote).status, 126);
  });
});

describe("the shape of the command line", { skip: IS_WINDOWS }, () => {
  const g = rig({ ALLOW_DESTRUCTIVE: "1", ALLOW_ADMIN: "1" });
  const CLP = g.clpctl;
  const ok = `sudo -n ${CLP} site:add:static '--domainName=a.example.com' '--siteUser=abc' '--siteUserPassword=${FIXED_PASSWORD}'`;

  it("accepts the reference command", () => {
    assert.equal(g.run(ok).status, 0);
  });

  const refused: [string, string | undefined][] = [
    ["no command (an interactive session)", undefined],
    ["an empty command", ""],
    ["another program", "sudo -n /bin/sh"],
    ["a shell after the program", `${ok}; id`],
    ["a pipe", `${ok} | cat`],
    ["a newline", `${ok}\nid`],
    ["a carriage return", `${ok}\rid`],
    ["a backtick", ok.replace("abc", "a`id`")],
    ["a dollar", ok.replace("abc", "a$HOME")],
    ["a double quote", ok.replace("'--siteUser=abc'", '"--siteUser=abc"')],
    ["a backslash", ok.replace("abc", "a\\b")],
    ["an unquoted option", ok.replace("'--siteUser=abc'", "--siteUser=abc")],
    ["a space inside a quoted value", ok.replace("abc", "a b")],
    ["sudo with another user", ok.replace("sudo -n", "sudo -u root")],
    ["sudo without -n", ok.replace("sudo -n", "sudo")],
    ["a relative program", ok.replace(CLP, "clpctl")],
    ["a program with a longer path", ok.replace(CLP, `${CLP}2`)],
    ["a path through env", `env ${ok}`],
    ["an unknown command", ok.replace("site:add:static", "site:add:wordpress")],
    ["an unknown option", `${ok} '--extra=1'`],
    ["a duplicated option", `${ok} '--siteUser=other'`],
    ["a missing required option", ok.replace(" '--siteUser=abc'", "")],
    ["an option the command lacks", ok.replace("'--siteUser=abc'", "'--phpVersion=8.4'")],
    ["a flag the command lacks", `${ok} '--force'`],
    ["a flag with a value", `sudo -n ${CLP} site:delete '--domainName=a.example.com' '--force=1'`],
    ["an option with an empty value", ok.replace("abc", "")],
    ["a bare option", `${ok} --force`],
    ["a positional argument", `${ok} 'extra'`],
    ["a value that fails its type", ok.replace("a.example.com", "A.example.com")],
    ["a reserved site user", ok.replace("abc", "root")],
    ["a password that is not generated-looking", ok.replace(FIXED_PASSWORD, "hunter2hunter2")],
    ["a line over 4096 characters", `${ok} '--x=${"a".repeat(4100)}'`],
    ["--help", `sudo -n ${CLP} '--help'`],
    ["--version", `sudo -n ${CLP} '--version'`],
    ["list", `sudo -n ${CLP} list`],
  ];
  for (const [name, command] of refused) {
    it(`refuses ${name}`, () => {
      const r = g.run(command);
      assert.equal(r.status, 126, `${JSON.stringify(command)} -> ${r.status} ${r.stderr}`);
      assert.match(r.stderr, /cloudpanel-mcp-gate: refused:/);
      assert.deepEqual(r.log, []);
    });
  }

  it("refuses a line over 4096 characters even when every part of it is valid", () => {
    const domain = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.example.com`;
    const many = Array.from({ length: 20 }, () => domain).join(",");
    const line = `sudo -n ${CLP} lets-encrypt:install:certificate '--domainName=a.example.com' '--subjectAlternativeName=${many}'`;
    assert.ok(line.length > 4096 && domain.length <= 253);
    assert.equal(g.run(line).status, 126);
    const shorter = `sudo -n ${CLP} lets-encrypt:install:certificate '--domainName=a.example.com' '--subjectAlternativeName=${Array.from({ length: 10 }, () => domain).join(",")}'`;
    assert.ok(shorter.length < 4096);
    assert.equal(g.run(shorter).status, 0, "the same shape, shorter, is accepted");
  });

  it("accepts a declared flag exactly once", () => {
    const del = `sudo -n ${CLP} site:delete '--domainName=a.example.com' '--force'`;
    assert.equal(g.run(del).status, 0);
    assert.equal(g.run(`${del} '--force'`).status, 126);
    assert.equal(g.run(`sudo -n ${CLP} site:delete '--domainName=a.example.com'`).status, 0, "the flag is optional");
  });
});

describe("protected targets in the gate", { skip: IS_WINDOWS }, () => {
  const g = rig({
    ALLOW_DESTRUCTIVE: "1", ALLOW_ADMIN: "1", PROTECT_DOMAINS: "(panel.example.com '*.prod.example.com')", PROTECT_DATABASES: "(maindb)", PROTECT_PANEL_USERS: "(owner)",
  });
  const CLP = g.clpctl;
  const del = (d: string): string => `sudo -n ${CLP} site:delete '--domainName=${d}' '--force'`;

  it("refuses a protected domain, with or without www, and a wildcard's whole subtree", () => {
    for (const d of ["panel.example.com", "www.panel.example.com", "a.prod.example.com", "a.b.prod.example.com", "prod.example.com", "www.prod.example.com"]) {
      assert.equal(g.run(del(d)).status, 126, d);
    }
    for (const d of ["other.example.com", "evilprod.example.com", "prod.example.com.evil.net", "example.com"]) assert.equal(g.run(del(d)).status, 0, d);
  });
  it("refuses protected databases and panel users", () => {
    assert.equal(g.run(`sudo -n ${CLP} db:delete '--databaseName=maindb'`).status, 126);
    assert.equal(g.run(`sudo -n ${CLP} db:delete '--databaseName=otherdb'`).status, 0);
    assert.equal(g.run(`sudo -n ${CLP} db:import '--databaseName=maindb' '--file=/var/lib/cloudpanel-mcp-server/dumps/x.sql'`).status, 126);
    assert.equal(g.run(`sudo -n ${CLP} db:import '--databaseName=otherdb' '--file=/var/lib/cloudpanel-mcp-server/dumps/x.sql'`).status, 0);
    for (const cmd of ["user:delete", "user:disable:mfa"]) {
      assert.equal(g.run(`sudo -n ${CLP} ${cmd} '--userName=owner'`).status, 126, cmd);
      assert.equal(g.run(`sudo -n ${CLP} ${cmd} '--userName=other'`).status, 0, cmd);
    }
    assert.equal(g.run(`sudo -n ${CLP} user:reset:password '--userName=owner' '--password=${FIXED_PASSWORD}'`).status, 126);
  });
});

describe("every protected option of the catalogue is enforced by the gate", { skip: IS_WINDOWS }, () => {
  const all = { ALLOW_WRITE: "1", ALLOW_DESTRUCTIVE: "1", ALLOW_ADMIN: "1" };
  const SETTING: Record<string, string> = { domain: "PROTECT_DOMAINS", siteUser: "PROTECT_SITE_USERS", database: "PROTECT_DATABASES", panelUser: "PROTECT_PANEL_USERS" };
  for (const spec of catalog.filter((s) => s.kind === "clpctl" && Object.keys(s.protectOptions).length > 0)) {
    it(`${spec.name}: each protected value refuses the command, entered in upper case in the settings`, () => {
      const plan = (spec.plan as NonNullable<typeof spec.plan>)(SAMPLE_ARGS[spec.name] ?? {}, profile);
      for (const [option, kind] of Object.entries(spec.protectOptions)) {
        const value = String(plan.options.find((o) => o.name === option)?.value);
        for (const part of value.split(",")) {
          const g = rig({ ...all, [SETTING[kind] as string]: `(${part.toUpperCase()})` });
          const r = g.run(commandFor(spec.name, g.clpctl).remote);
          assert.equal(r.status, 126, `${option} ${kind} ${part}: ${r.stderr}`);
          assert.match(r.stderr, /protected/);
          assert.deepEqual(r.log, []);
        }
      }
    });
  }
  it("a value that is not protected still goes through", () => {
    const g = rig({ ...all, PROTECT_DOMAINS: "(other.example.com)", PROTECT_SITE_USERS: "(other)", PROTECT_DATABASES: "(other)", PROTECT_PANEL_USERS: "(other)" });
    for (const spec of catalog.filter((s) => s.kind === "clpctl" && Object.keys(s.protectOptions).length > 0)) {
      assert.equal(g.run(commandFor(spec.name, g.clpctl).remote).status, 0, spec.name);
    }
  });
  it("one protected entry among several in a list refuses the whole command", () => {
    const g = rig({ ...all, PROTECT_DOMAINS: "(b.example.com)" });
    const line = (sans: string): string => `sudo -n ${g.clpctl} lets-encrypt:install:certificate '--domainName=a.example.com' '--subjectAlternativeName=${sans}'`;
    assert.equal(g.run(line("c.example.com,d.example.com")).status, 0);
    assert.equal(g.run(line("c.example.com,b.example.com")).status, 126);
    assert.equal(g.run(line("www.b.example.com,c.example.com")).status, 126);
    assert.equal(g.run(line("c.example.com,b.example.com,d.example.com")).status, 126);
    assert.equal(g.run(line("c.example.com,d.example.com,e.example.com")).status, 0);
  });
  it("the protected-target check splits its list without a here-string, which could fail and leave nothing to check", () => {
    const start = text.indexOf("# protected targets");
    const end = text.indexOf('log_line "accepted: $sub"');
    assert.ok(start > 0 && end > start);
    assert.ok(!text.slice(start, end).includes("<<<"), text.slice(start, end));
  });
  it("a malformed protect setting stops every command instead of protecting nothing", () => {
    for (const bad of ["('a;b')", "('')", "('a b')", "('*')", "('$x')"]) {
      const g = rig({ ...all, PROTECT_DOMAINS: bad });
      const r = g.run(commandFor("clp_site_add_static", g.clpctl).remote);
      assert.equal(r.status, 126, bad);
      assert.match(r.stderr, /malformed/);
    }
  });
  it("a setting that is not a name of its kind stops every command: a trailing dot, one label, an underscore, a wildcard alone", () => {
    const bad: [string, string][] = [
      ["PROTECT_DOMAINS", "(example.com.)"],
      ["PROTECT_DOMAINS", "(localhost)"],
      ["PROTECT_DOMAINS", "(a_b.example.com)"],
      ["PROTECT_DOMAINS", "('*.')"],
      ["PROTECT_DOMAINS", "('*.example.com.')"],
      ["PROTECT_DOMAINS", "('**.example.com')"],
      ["PROTECT_DOMAINS", "('a.*.example.com')"],
      ["PROTECT_DOMAINS", "(-a.example.com)"],
      ["PROTECT_SITE_USERS", "(1abc)"],
      ["PROTECT_SITE_USERS", "(a.b)"],
      ["PROTECT_SITE_USERS", "(-x)"],
      ["PROTECT_DATABASES", "(a_b)"],
      ["PROTECT_DATABASES", "(-x)"],
      ["PROTECT_DATABASES", "(a.b)"],
      ["PROTECT_PANEL_USERS", "(-x)"],
      ["PROTECT_PANEL_USERS", "(a@b)"],
      ["PROTECT_PANEL_USERS", "(a/b)"],
    ];
    for (const [setting, value] of bad) {
      const g = rig({ ...all, [setting]: value });
      const r = g.run(commandFor("clp_site_add_static", g.clpctl).remote);
      assert.equal(r.status, 126, `${setting}=${value}`);
      assert.match(r.stderr, new RegExp(`${setting} setting of the gate is malformed`), `${setting}=${value}`);
    }
  });
  it("settings that are names of their kind are accepted, in any case", () => {
    const g = rig({ ...all, PROTECT_DOMAINS: "(Example.COM '*.Prod.Example.com')", PROTECT_SITE_USERS: "(Shop)", PROTECT_DATABASES: "(MainDB db-2)", PROTECT_PANEL_USERS: "(Owner john.doe)" });
    assert.equal(g.run(commandFor("clp_site_add_static", g.clpctl).remote).status, 0);
  });
  it("ignores every leading www.: www.www.example.com is the protected site's other form", () => {
    const g = rig({ ...all, PROTECT_DOMAINS: "(example.com '*.prod.example.org')" });
    const del = (d: string): number | null => g.run(`sudo -n ${g.clpctl} site:delete '--domainName=${d}' '--force'`).status;
    for (const d of ["example.com", "www.example.com", "www.www.example.com", "www.www.www.example.com", "www.www.prod.example.org", "prod.example.org"]) assert.equal(del(d), 126, d);
    for (const d of ["wwwexample.com", "www-example.com", "www.example.com.evil.net", "xwww.example.com"]) assert.equal(del(d), 0, d);
  });
  it("a site user's gate protects the account it runs as", () => {
    const me = userInfo().username;
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(me) || process.getuid?.() === 0) return; // an account name outside the site-user pattern cannot be listed; root is refused by a site-user gate
    const tool = "clp_system_permissions_reset";
    const protectedGate = rig({ ...all, SCOPE: "siteuser", PROTECT_SITE_USERS: `(${me.toUpperCase()})` });
    const r = protectedGate.run(commandFor(tool, protectedGate.clpctl, []).remote);
    assert.equal(r.status, 126, r.stderr);
    assert.match(r.stderr, /protected/);
    const other = rig({ ...all, SCOPE: "siteuser", PROTECT_SITE_USERS: "(somebody-else)" });
    assert.equal(other.run(commandFor(tool, other.clpctl, []).remote).status, 0);
    const none = rig({ ...all, SCOPE: "siteuser" });
    assert.equal(none.run(commandFor("clp_varnish_cache_purge", none.clpctl, []).remote).status, 0);
    // a root gate does not look at the account
    const root = rig({ ...all, PROTECT_SITE_USERS: `(${me})` });
    assert.equal(root.run(commandFor("clp_site_delete", root.clpctl).remote).status, 0);
  });
  it("refuses the database accounts that belong to the system", () => {
    const g = rig(all);
    const add = (user: string): number | null =>
      g.run(`sudo -n ${g.clpctl} db:add '--domainName=a.example.com' '--databaseName=shopdb' '--databaseUserName=${user}' '--databaseUserPassword=${FIXED_PASSWORD}'`).status;
    for (const user of ["root", "ROOT", "Root", "mysql", "MySQL", "clp", "cloudpanel", "debian_sys_maint", "mysql_sys", "mariadb_sys", "sys"]) assert.equal(add(user), 126, user);
    for (const user of ["shop_user", "rooty", "myroot", "mysql2", "app"]) assert.equal(add(user), 0, user);
  });
});

describe("files in the gate: a subdirectory and extensions per kind", { skip: IS_WINDOWS }, () => {
  const all = { ALLOW_WRITE: "1", ALLOW_DESTRUCTIVE: "1", ALLOW_ADMIN: "1" };
  const D = "/var/lib/cloudpanel-mcp-server";
  const run = (g: GateRig, command: string, options: string): number | null => g.run(`sudo -n ${g.clpctl} ${command} ${options}`).status;
  const export_ = (g: GateRig, file: string): number | null => run(g, "db:export", `'--databaseName=shopdb' '--file=${file}'`);
  const template = (g: GateRig, file: string): number | null => run(g, "vhost-template:add", `'--name=My' '--file=${file}'`);
  const install = (g: GateRig, key: string, cert: string): number | null => run(g, "site:install:certificate", `'--domainName=a.example.com' '--privateKey=${key}' '--certificate=${cert}'`);

  it("a dump goes to dumps/, a template is read from templates/, a certificate from certs/, and nowhere else", () => {
    const g = rig(all);
    assert.equal(export_(g, `${D}/dumps/a.sql.gz`), 0);
    assert.equal(export_(g, `${D}/a.sql`), 126);
    assert.equal(export_(g, `${D}/templates/a.sql`), 126);
    assert.equal(export_(g, `${D}/certs/a.sql`), 126);
    assert.equal(template(g, `${D}/templates/a.tpl`), 0);
    assert.equal(template(g, `${D}/dumps/a.tpl`), 126, "a file written by an export can never be a template");
    assert.equal(template(g, `${D}/dumps/a.sql`), 126);
    assert.equal(install(g, `${D}/certs/a.key`, `${D}/certs/a.pem`), 0);
    assert.equal(install(g, `${D}/dumps/a.key`, `${D}/certs/a.pem`), 126);
    assert.equal(install(g, `${D}/certs/a.key`, `${D}/dumps/a.sql`), 126);
  });
  it("several directories each have their own subdirectories", () => {
    const g = rig({ ...all, ALLOWED_FILE_DIRS: "(/srv/a /srv/b)" });
    assert.equal(export_(g, "/srv/b/dumps/x.sql"), 0);
    assert.equal(export_(g, "/srv/a/x.sql"), 126);
    assert.equal(export_(g, `${D}/dumps/x.sql`), 126);
  });
});

describe("application ports in the gate", { skip: IS_WINDOWS }, () => {
  const all = { ALLOW_WRITE: "1" };
  const node = (g: GateRig, port: string): number | null =>
    g.run(`sudo -n ${g.clpctl} site:add:nodejs '--domainName=a.example.com' '--nodejsVersion=22' '--appPort=${port}' '--siteUser=abc' '--siteUserPassword=${FIXED_PASSWORD}'`).status;
  const proxy = (g: GateRig, url: string): number | null =>
    g.run(`sudo -n ${g.clpctl} site:add:reverse-proxy '--domainName=a.example.com' '--reverseProxyUrl=${url}' '--siteUser=abc' '--siteUserPassword=${FIXED_PASSWORD}'`).status;

  it("the default list is the server's default list", () => {
    const g = rig(all);
    for (const p of ["1337", "2368", "3000", "4999", "5000", "5173", "8000", "8080", "8199"]) assert.equal(node(g, p), 0, p);
    for (const p of ["1024", "5001", "8200", "9000", "39400", "3306", "22", "80"]) assert.equal(node(g, p), 126, p);
    assert.equal(proxy(g, "http://127.0.0.1:8000"), 0);
    assert.equal(proxy(g, "http://127.0.0.1:443"), 0);
    assert.equal(proxy(g, "http://127.0.0.1:9000"), 126);
  });
  it("the setting replaces the list, in single ports and low-high ranges", () => {
    const g = rig({ ...all, APP_PORTS: "(39400-39409 5173)" });
    for (const p of ["39400", "39405", "39409", "5173"]) assert.equal(node(g, p), 0, p);
    for (const p of ["18479", "18490", "3000", "5174"]) assert.equal(node(g, p), 126, p);
    assert.equal(proxy(g, "http://127.0.0.1:39405"), 0);
    assert.equal(proxy(g, "http://127.0.0.1:3000"), 126);
  });
  it("the denied ports stay denied inside a range the setting lists", () => {
    const g = rig({ ...all, APP_PORTS: "(1024-65535)" });
    for (const p of ["3306", "6379", "8443", "2375", "9200", "8200", "4646", "8001", "3389"]) assert.equal(node(g, p), 126, p);
    assert.equal(node(g, "9000"), 0);
  });
  it("a setting that is not a port or a range of 1024-65535, or names a port the server never allows, stops every command", () => {
    for (const bad of ["(abc)", "('3000;')", "(3000-)", "(-3000)", "(4000-3000)", "(80)", "(80-3000)", "(1023)", "(65536)", "(3000-70000)", "(3306)", "(8443 3000)", "(0)", "(3000--4000)"]) {
      const g = rig({ ...all, APP_PORTS: bad });
      const r = g.run(commandFor("clp_site_add_static", g.clpctl).remote);
      assert.equal(r.status, 126, bad);
      assert.match(r.stderr, /APP_PORTS setting of the gate is malformed/, bad);
    }
    // no entry at all allows no port, and says nothing
    const none = rig({ ...all, APP_PORTS: "()" });
    assert.equal(node(none, "3000"), 126);
    assert.equal(none.run(commandFor("clp_site_add_static", none.clpctl).remote).status, 0);
  });
});

describe("the directories and hosts the gate is set up with", { skip: IS_WINDOWS }, () => {
  const all = { ALLOW_WRITE: "1", ALLOW_DESTRUCTIVE: "1", ALLOW_ADMIN: "1" };
  const stop = (settings: Record<string, string>, pattern: RegExp, name: string): void => {
    const g = rig({ ...all, ...settings });
    const r = g.run(commandFor("clp_site_add_static", g.clpctl).remote);
    assert.equal(r.status, 126, name);
    assert.match(r.stderr, pattern, name);
  };

  it("refuses a file directory in a system place, in a place other accounts write, too shallow or not clean", () => {
    const badDirs = [
      "/tmp", "/tmp/mcp", "/tmp/a/b", "/home/shop/mcp", "/var/tmp/x", "/var/www/x/y", "/var/mail/x", "/var/spool/mail", "/var/lock/mcp", "/var/crash/mcp", "/var/lib/php/sessions",
      "/mnt/x/y", "/media/x/y", "/etc/mcp", "/usr/local/x", "/run/x/y", "/var/run/mcp", "/dev/shm/x", "/root/x",
      "/data", "/", "relative/dir", "/var/lib/x/", "/var/lib//x", "/var/lib/./x", "/var/lib/x/..", "/var/lib/a b", "/var/lib/$x",
    ];
    for (const dir of badDirs) stop({ ALLOWED_FILE_DIRS: `('${dir}')` }, /ALLOWED_FILE_DIRS setting of the gate is not a usable directory/, dir);
    stop({ ALLOWED_FILE_DIRS: "(/var/lib/mcp-ok /tmp/x)" }, /ALLOWED_FILE_DIRS/, "one bad entry among good ones");
  });
  it("accepts root-owned places, and a shared one only when the setting says so; system places never", () => {
    for (const dir of ["/var/lib/cloudpanel-mcp-server", "/srv/cloudpanel/exchange", "/opt/cloudpanel-mcp/files", "/home-backup/x/y", "/tmpx/a/b", "/var/wwwx/a"]) {
      const g = rig({ ...all, ALLOWED_FILE_DIRS: `(${dir})` });
      assert.equal(g.run(commandFor("clp_site_add_static", g.clpctl).remote).status, 0, dir);
    }
    const lax = rig({ ...all, ALLOWED_FILE_DIRS: "(/home/deploy/mcp-test)", ALLOW_UNTRUSTED_FILE_DIRS: "1" });
    assert.equal(lax.run(commandFor("clp_site_add_static", lax.clpctl).remote).status, 0);
    for (const dir of ["/etc/mcp", "/usr/local/x", "/run/x/y", "/var/run/mcp", "/dev/shm/x"]) stop({ ALLOWED_FILE_DIRS: `(${dir})`, ALLOW_UNTRUSTED_FILE_DIRS: "1" }, /ALLOWED_FILE_DIRS/, `${dir} even when untrusted places are allowed`);
    const strict = rig({ ...all, ALLOWED_FILE_DIRS: "(/home/deploy/mcp-test)", ALLOW_UNTRUSTED_FILE_DIRS: "0" });
    assert.equal(strict.run(commandFor("clp_site_add_static", strict.clpctl).remote).status, 126);
  });
  it("no directory at all allows no file", () => {
    const g = rig({ ...all, ALLOWED_FILE_DIRS: "()" });
    assert.equal(g.run(commandFor("clp_db_export", g.clpctl).remote).status, 126);
    assert.equal(g.run(commandFor("clp_site_add_static", g.clpctl).remote).status, 0);
  });
  it("refuses a proxy host that is not a lowercase host name or an IPv6 address", () => {
    for (const bad of ["(LOCALHOST)", "(http://x)", "('a b')", "('a;b')", "(-x)", "(x-)", "('[::1]')", "('::g')", "('')"]) stop({ PROXY_HOSTS: bad }, /PROXY_HOSTS setting of the gate is malformed/, bad);
    for (const ok of ["(127.0.0.1 localhost ::1)", "(app.internal)", "(10.0.0.5 fe80::1)", "()"]) {
      const g = rig({ ...all, PROXY_HOSTS: ok });
      assert.equal(g.run(commandFor("clp_site_add_static", g.clpctl).remote).status, 0, ok);
    }
  });
});

describe("a site-user gate must run as a site user", { skip: IS_WINDOWS || process.getuid?.() === 0 }, () => {
  const tool = "clp_system_permissions_reset";
  const siteGate = (settings: Record<string, string> = {}, replacements: [string, string][] = []) => rig({ ALLOW_WRITE: "1", SCOPE: "siteuser", ...settings }, replacements);

  it("works for an ordinary account", () => {
    const g = siteGate();
    assert.equal(g.run(commandFor(tool, g.clpctl, []).remote).status, 0);
  });
  it("refuses to run as root", () => {
    const g = siteGate({}, [["id -u 2>/dev/null", "echo 0"]]);
    const r = g.run(commandFor(tool, g.clpctl, []).remote);
    assert.equal(r.status, 126);
    assert.match(r.stderr, /does not run as root/);
  });
  it("refuses to run as a system account", () => {
    const me = userInfo().username;
    const g = siteGate({ RESERVED_SITE_USERS: `(root clp ${me})` });
    const r = g.run(commandFor(tool, g.clpctl, []).remote);
    assert.equal(r.status, 126);
    assert.match(r.stderr, /does not run as a system account/);
  });
});

describe("the gate does not trust its caller's PATH", { skip: IS_WINDOWS }, () => {
  it("a poisoned tr earlier in PATH is never run", () => {
    const g = rig({ ALLOW_WRITE: "1", ALLOW_DESTRUCTIVE: "1" });
    const evil = shortTmp("clpe-");
    const marker = join(evil, "ran");
    writeExecutable(evil, "tr", `#!/bin/sh\ntouch "${marker}"\ncat\n`);
    const r = g.run(`sudo -n ${g.clpctl} db:delete '--databaseName=abc'`, undefined, { PATH: `${evil}:/usr/bin:/bin` });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!existsSync(marker), "the gate ran a program from the caller's PATH");
  });
});

describe("rules between options", { skip: IS_WINDOWS }, () => {
  it("sites only with role user", () => {
    const g = rig({ ALLOW_ADMIN: "1" });
    const base = (role: string, sites: string[]): string =>
      [`sudo -n ${g.clpctl} user:add`, "'--userName=jane'", "'--email=jane@example.com'", "'--firstName=Jane'", "'--lastName=Doe'", `'--password=${FIXED_PASSWORD}'`, `'--role=${role}'`, ...sites, "'--timezone=UTC'", "'--status=1'"].join(" ");
    assert.equal(g.run(base("user", ["'--sites=a.example.com'"])).status, 0);
    assert.equal(g.run(base("admin", ["'--sites=a.example.com'"])).status, 126);
    assert.equal(g.run(base("admin", [])).status, 0);
  });
});

describe("the gate's value types agree with the server's", { skip: IS_WINDOWS }, () => {
  const used = new Set<OptionType>();
  for (const spec of catalog) for (const o of Object.values(spec.options)) used.add(o.type);

  const SEEDS: Partial<Record<OptionType, string[]>> = {
    dumpPath: [`${DIRP}/dumps/a.sql`, `${DIRP}/dumps/a.sql.gz`, `${DIRP}/dumps/x/y.sql`, `${DIRP}/dumps/a.sqlx`, `${DIRP}/dumps/a.sql.bak`, `${DIRP}/dumps/.sql`, `${DIRP}/dumps/a.gz`, `${DIRP}/a.sql`, `${DIRP}/dumps`, `${DIRP}/dumps/`, `${DIRP}/dumps/.sql`, `${DIRP}/certs/a.sql`, `${DIRP}/templates/a.sql`, `${DIRP}/dumps-x/a.sql`, `${DIRP}-evil/dumps/a.sql`, `${DIRP}/dumps/../a.sql`, `${DIRP}/dumps//a.sql`, `${DIRP}/dumps/./a.sql`, `${DIRP}/dumps/a b.sql`, "/tmp/dumps/a.sql", "/etc/passwd"],
    certPath: [`${DIRP}/certs/a.key`, `${DIRP}/certs/a.pem`, `${DIRP}/certs/a.crt`, `${DIRP}/certs/a.cer`, `${DIRP}/certs/a.cert`, `${DIRP}/certs/a.chain`, `${DIRP}/certs/a.ca-bundle`, `${DIRP}/certs/x/y.pem`, `${DIRP}/certs/a.sql`, `${DIRP}/certs/a.txt`, `${DIRP}/certs/a.pem.bak`, `${DIRP}/certs/pem`, `${DIRP}/dumps/a.pem`, `${DIRP}/a.pem`, `${DIRP}/certs`, `${DIRP}/certs/`, `${DIRP}/certs/../a.pem`],
    templatePath: [`${DIRP}/templates/a.tpl`, `${DIRP}/templates/a.conf`, `${DIRP}/templates/x/y.tpl`, `${DIRP}/templates/a.txt`, `${DIRP}/templates/a.tpl.bak`, `${DIRP}/templates/a.pem`, `${DIRP}/dumps/a.tpl`, `${DIRP}/a.tpl`, `${DIRP}/templates`, `${DIRP}/templates/`, `${DIRP}/templates/../a.conf`],
    proxyUrl: ["http://127.0.0.1:8000", "http://localhost", "https://localhost:8443/app", "http://[::1]:3000", "http://127.0.0.1/", "http://127.0.0.1:80", "http://127.0.0.1:443", "http://127.0.0.1:22", "http://127.0.0.1:2375", "http://127.0.0.1:65535", "http://127.0.0.1:65536", "http://10.0.0.1:8000", "http://127.0.0.1.evil.com", "http://127.0.0.1:8000/a/../b", "http://127.0.0.1:8000//a", "http://127.0.0.1:8000/a.b-c_d", "http://LOCALHOST", "http://localhost:1024", "http://localhost:1023", "http://127.0.0.1:3000", "http://127.0.0.1:4999", "http://127.0.0.1:5000", "http://127.0.0.1:5001", "http://127.0.0.1:5173", "http://127.0.0.1:8199", "http://127.0.0.1:8200", "http://127.0.0.1:9000", "http://127.0.0.1:1337", "http://127.0.0.1:2368", "http://127.0.0.1:3306"],
    domainList: ["a.example.com", "a.example.com,b.example.com", "a.example.com,", ",a.example.com", "a.example.com,,b.example.com", Array.from({ length: 20 }, (_, i) => `a${i}.example.com`).join(","), Array.from({ length: 21 }, (_, i) => `a${i}.example.com`).join(","), "A.example.com,b.example.com", "a.example.com, b.example.com"],
    port: ["3000", "03000", "0", "1", "1023", "1024", "65535", "65536", "3306", "8443", "6081", "6379", "22", "80", "3000 ", "+3000", "3e3", "99999", "100000", "8080", "1336", "1337", "1338", "2367", "2368", "2369", "2999", "4999", "5000", "5001", "5172", "5173", "5174", "7999", "8000", "8199", "8200", "9000", "39400"],
    purge: ["all", "ALL", "all,a", "a,all", "a", "a,b", "a,", ",a", "a,,b", "https://www.example.com/x.html", "http://www.example.com", "https://www.example.com:8443/x", "https://127.0.0.1/x", "https://localhost/x", "https://www.example.com/x?y=1", Array.from({ length: 20 }, (_, i) => `t${i}`).join(","), Array.from({ length: 21 }, (_, i) => `t${i}`).join(","), "-x", "x-"],
    role: ["admin", "site-manager", "user", "Admin", "root", "", "user "],
    status: ["0", "1", "2", "01", "", "true"],
    channel: ["stable", "test", "Test", "beta", ""],
    password: [FIXED_PASSWORD, FIXED_PASSWORD.slice(1), `${FIXED_PASSWORD}A`, "!".repeat(32), ""],
    siteUser: ["shop", "root", "clp", "Shop", "www-data", "a", "mysql", "nginx", "john-doe"],
    userDbName: ["shopdb", "mysql", "MySQL", "sys", "SYS", "information_schema", "performance_schema", "clp", "CLP", "cloudpanel", "my_db", "my-db", "-db"],
    dbUser: ["shop_user", "john", "root", "ROOT", "Root", "mysql", "MySQL", "mysqld", "mariadb", "clp", "cloudpanel", "debian_sys_maint", "debian-sys-maint", "mysql_sys", "mariadb_sys", "mysql_session", "mysql_infoschema", "sys", "rooty", "myroot", "a", "a".repeat(64), "a".repeat(65), "-x", "x y"],
    email: ["a@example.com", `${"a".repeat(64)}@example.com`, `a@${"b".repeat(240)}.com`, "a@b.c", "a@b.co"],
  };

  function corpus(type: OptionType): string[] {
    const pattern = type in SOURCES ? (type as PatternName) : undefined;
    const seeds = [
      ...(SEEDS[type] ?? []),
      ...(pattern === undefined ? [] : fc.sample(fc.stringMatching(RE[pattern]), 60)),
      ...HOSTILE.filter((v) => !v.includes("\0")),
    ];
    const mutations = ["x", "-", " ", "'", "\n", ";", ".", "/", "..", ":", "A", "9"];
    const out = new Set<string>(seeds);
    for (const seed of seeds.slice(0, 40)) {
      for (const m of mutations) {
        out.add(seed + m);
        out.add(m + seed);
        out.add(seed.slice(0, -1));
      }
    }
    return [...out].slice(0, 700);
  }

  for (const bash of BASHES) {
    it(`agrees on every value of every option type (${bash})`, () => {
      const dir = shortTmp("clpg-");
      const lib = join(dir, "lib.sh");
      writeFileSync(lib, text.replace(/\nmain\n$/, "\n"));
      const driver = writeExecutable(dir, "driver.sh", `#!${bash}\nsource "$1"\nwhile IFS= read -r -d '' type && IFS= read -r -d '' value; do\n  if valid_value "$type" "$value"; then echo 1; else echo 0; fi\ndone\n`);
      const inputs: { type: OptionType; value: string }[] = [];
      for (const type of used) for (const value of corpus(type)) inputs.push({ type, value });
      assert.ok(inputs.length > 5000);
      const stdin = inputs.map((i) => `${i.type}\0${i.value}\0`).join("");
      const r = spawnSync(bash, [driver, lib], { input: stdin, encoding: "utf8", maxBuffer: 50 * 1024 * 1024 });
      assert.equal(r.status, 0, r.stderr);
      const answers = r.stdout.trim().split("\n");
      assert.equal(answers.length, inputs.length);
      const disagreements: string[] = [];
      inputs.forEach((input, i) => {
        const gate = answers[i] === "1";
        const server = isValidOption(input.type, input.value, CTX);
        if (gate !== server) disagreements.push(`${input.type} ${JSON.stringify(input.value)}: server ${server}, gate ${gate}`);
      });
      assert.deepEqual(disagreements.slice(0, 10), [], `${disagreements.length} disagreements`);
      const accepted = answers.filter((a) => a === "1").length;
      assert.ok(accepted > 500 && accepted < inputs.length, `corpus too one-sided: ${accepted}/${inputs.length}`);
    });
  }

  it("covers every option type the tools use", () => {
    for (const type of ["domain", "siteUser", "userDbName", "port", "domainList", "dumpPath", "certPath", "templatePath", "proxyUrl", "purge", "role", "status", "channel", "password", "email"] as OptionType[]) {
      assert.ok(used.has(type), type);
    }
  });
});

describe("on every bash we have", { skip: IS_WINDOWS }, () => {
  for (const bash of BASHES) {
    it(`accepts the reference command and refuses an injection (${bash})`, () => {
      const g = rig();
      const ok = `sudo -n ${g.clpctl} site:add:static '--domainName=a.example.com' '--siteUser=abc' '--siteUserPassword=${FIXED_PASSWORD}'`;
      assert.equal(g.run(ok, bash).status, 0);
      assert.equal(g.run(`${ok}; id`, bash).status, 126);
      assert.equal(g.run(ok.replace("abc", "a'b"), bash).status, 126);
    });
  }
});

