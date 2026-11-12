import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { IS_WINDOWS, ROOT, installSimClpctl, shortTmp } from "./helpers.ts";
import type { SimState } from "./sim/clpctl.ts";

const SCRIPT = join(ROOT, "scripts", "contract-test.mjs");
const run = (args: string[], env: Record<string, string> = {}) =>
  spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: process.env["HOME"] ?? "/tmp", ...env }, timeout: 120_000 });

describe("the live contract-test script", { skip: IS_WINDOWS }, () => {
  it("refuses to run without the long confirmation flag", () => {
    const r = run(["--local", "--file-dir", "/tmp/x/files"]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /i-understand-this-creates-and-deletes-things/);
  });

  it("refuses unclear targets and unsafe directories", () => {
    const flag = "--i-understand-this-creates-and-deletes-things";
    assert.equal(run([flag, "--file-dir", "/tmp/x/files"]).status, 2, "no server");
    assert.equal(run([flag, "--local", "--ssh-host", "h", "--file-dir", "/tmp/x/files"]).status, 2, "two servers");
    assert.equal(run([flag, "--local", "--file-dir", "relative/dir"]).status, 2, "relative directory");
    assert.equal(run([flag, "--local", "--file-dir", "/tmp/x/files", "--only", "everything"]).status, 2, "unknown family");
    for (const host of ["-oProxyCommand=id", "-x", "a b", "a;b", "a\nb", "a'b", "", "$(id)"]) {
      assert.equal(run([flag, "--ssh-host", host, "--file-dir", "/tmp/x/files"]).status, 2, `host ${JSON.stringify(host)}`);
      assert.equal(run(["--plan", "--ssh-host", host, "--file-dir", "/tmp/x/files"]).status, 2, `plan, host ${JSON.stringify(host)}`);
    }
  });

  it("--plan lists exactly what would be created and touches nothing", () => {
    const r = run(["--plan", "--ssh-host", "my-server", "--file-dir", "/var/lib/contract-test", "--only", "static,database,user"]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /ssh my-server/);
    assert.match(r.stdout, /mcp-test-static-[0-9a-f]{6}\.example\.invalid/);
    assert.match(r.stdout, /clp_db_add mcptdata[0-9a-f]{6}/);
    assert.match(r.stdout, /Everything created is deleted at the end/);
    assert.match(r.stdout, /\/var\/lib\/contract-test\/dumps, \/var\/lib\/contract-test\/certs and \/var\/lib\/contract-test\/templates/);
    assert.match(r.stdout, /--file-dir\/dumps/);
    assert.ok(!r.stdout.includes("[certificate]"));
  });

  it("runs every family against the simulator, approves only its own throwaway names, and leaves nothing behind", () => {
    const dir = shortTmp("clpc-");
    const files = join(dir, "files");
    mkdirSync(files);
    const clpctl = installSimClpctl(join(dir, "bin"));
    const state = join(dir, "sim.json");
    const report = join(dir, "report.md");
    const r = run(
      ["--i-understand-this-creates-and-deletes-things", "--local", "--elevation", "none", "--clpctl-path", clpctl, "--file-dir", files, "--only", "read,static,proxy,php,nodejs,python,database,certificate,template,user,cloudflare,panel,master-credentials", "--report", report],
      { CLPCTL_SIM_STATE: state },
    );
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /ALL PASSED/);
    assert.ok(!/FAIL/.test(r.stdout.replace(/ALL PASSED/g, "")), r.stdout);
    const sim = JSON.parse(readFileSync(state, "utf8")) as SimState;
    assert.deepEqual(sim.sites, [], "every site was deleted");
    assert.deepEqual(sim.users.map((u) => u.userName), ["admin"], "every panel user was deleted");
    assert.ok(sim.templates.every((t) => t.type === "System"), "every template was deleted");
    assert.equal(sim.basicAuth, null);
    assert.match(readFileSync(report, "utf8"), /PASS {2}clp_db_import \(absolute path\)/);
    assert.match(r.stdout, /PASS {2}the directories this run made are removed/);
    assert.deepEqual(readdirSync(files), [], "the subdirectories and the files this run made are gone");
    assert.ok(!r.stdout.includes("SIM-MASTER-PASSWORD"));
  });

  it("creates --file-dir and its subdirectories when they are missing, and removes exactly those it made", () => {
    const dir = shortTmp("clpc-");
    const base = join(dir, "does", "not", "exist");
    const clpctl = installSimClpctl(join(dir, "bin"));
    const flags = ["--i-understand-this-creates-and-deletes-things", "--local", "--elevation", "none", "--clpctl-path", clpctl, "--file-dir", base, "--only", "database,certificate,template"];
    const r = run(flags, { CLPCTL_SIM_STATE: join(dir, "sim.json") });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.ok(!existsSync(join(base, "dumps")) && !existsSync(join(base, "certs")) && !existsSync(join(base, "templates")) && !existsSync(base), "everything it made is gone");
    assert.ok(existsSync(join(dir, "does")), "what it did not make is left alone");
  });

  it("leaves a subdirectory that already existed, and anything in it, alone", () => {
    const dir = shortTmp("clpc-");
    const files = join(dir, "files");
    mkdirSync(join(files, "dumps"), { recursive: true });
    writeFileSync(join(files, "dumps", "operators-own.sql"), "-- keep me\n");
    const clpctl = installSimClpctl(join(dir, "bin"));
    const r = run(["--i-understand-this-creates-and-deletes-things", "--local", "--elevation", "none", "--clpctl-path", clpctl, "--file-dir", files, "--only", "database,certificate,template"], { CLPCTL_SIM_STATE: join(dir, "sim.json") });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.deepEqual(readdirSync(files), ["dumps"]);
    assert.deepEqual(readdirSync(join(files, "dumps")), ["operators-own.sql"]);
  });

  it("deletes what it created even when a step fails", () => {
    const dir = shortTmp("clpc-");
    const files = join(dir, "files");
    mkdirSync(files);
    const clpctl = installSimClpctl(join(dir, "bin"));
    const state = join(dir, "sim.json");
    // PHP 7.0 is not installed in the simulator: the php step fails, the earlier static site must still be gone
    const r = run(
      ["--i-understand-this-creates-and-deletes-things", "--local", "--elevation", "none", "--clpctl-path", clpctl, "--file-dir", files, "--only", "static,php", "--php", "7.0"],
      { CLPCTL_SIM_STATE: state },
    );
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stdout, /FAIL {2}clp_site_add_php/);
    const sim = JSON.parse(readFileSync(state, "utf8")) as SimState;
    assert.deepEqual(sim.sites, []);
  });
});
