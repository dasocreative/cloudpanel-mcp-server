import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { loadConfig } from "../src/config/load.ts";
import { initConfigText, parseInitArgs } from "../src/init.ts";
import { DIST_ENTRY, IS_WINDOWS, SIM_DIR, installSimClpctl, shortTmp } from "./helpers.ts";

describe("--init options", () => {
  it("has safe, simple defaults: read-only, the dedicated account and key of the setup script", () => {
    const o = parseInitArgs(["--init", "--host", "203.0.113.10"]);
    assert.deepEqual(o, { profile: "default", host: "203.0.113.10", user: "cloudpanel-mcp", identityFile: "~/.ssh/id_ed25519_cloudpanel", port: undefined, allow: [] });
  });
  it("takes --name value and --name=value, and a class list", () => {
    const o = parseInitArgs(["--init", "--host=my-server", "--user", "deploy", "--port=2222", "--allow", "read,write,destructive", "--profile", "shop"]);
    assert.equal(o.host, "my-server");
    assert.equal(o.user, "deploy");
    assert.equal(o.port, 2222);
    assert.deepEqual(o.allow, ["write", "destructive"]);
    assert.equal(o.profile, "shop");
  });
  it("refuses what it does not know instead of guessing", () => {
    assert.throws(() => parseInitArgs(["--init"]), /needs --host/);
    assert.throws(() => parseInitArgs(["--init", "--host", "a", "--allow", "everything"]), /--allow takes/);
    assert.throws(() => parseInitArgs(["--init", "--host", "a", "--port", "0"]), /1-65535/);
    assert.throws(() => parseInitArgs(["--init", "--host", "a", "--frobnicate", "1"]), /unknown option/);
    assert.throws(() => parseInitArgs(["--init", "--host"]), /needs a value/);
  });
  it("writes a configuration the server loads as it was meant", () => {
    const text = initConfigText(parseInitArgs(["--init", "--host", "203.0.113.10", "--allow", "write"]));
    const config = loadConfig({ env: { CLOUDPANEL_MCP_CONFIG: "/x/config.json" }, readFile: () => text, fileMode: () => 0o100600, home: "/home/me", platform: "linux" });
    const p = config.profiles[0]!;
    assert.equal(config.defaultProfile, "default");
    assert.equal(p.target.kind, "ssh");
    const ssh = p.target.kind === "ssh" ? p.target.ssh : null;
    assert.equal(ssh?.host, "203.0.113.10");
    assert.equal(ssh?.user, "cloudpanel-mcp");
    assert.equal(ssh?.identityFile, "/home/me/.ssh/id_ed25519_cloudpanel");
    assert.equal(ssh?.port, undefined);
    assert.equal(p.elevation, "sudo");
    assert.deepEqual([...p.allow], ["write"]);
  });
});

describe("CLI --init", { skip: !existsSync(DIST_ENTRY) || IS_WINDOWS }, () => {
  function run(args: string[], config: string, extra: Record<string, string> = {}) {
    const dir = shortTmp("clpi-");
    const clpctl = installSimClpctl(join(dir, "bin"));
    return {
      clpctl,
      result: spawnSync(process.execPath, [DIST_ENTRY, "--init", ...args], {
        encoding: "utf8",
        env: {
          PATH: `${join(SIM_DIR, "bin")}:${process.env["PATH"] ?? "/usr/bin:/bin"}`,
          HOME: shortTmp("clph-"),
          CLOUDPANEL_MCP_STATE_DIR: shortTmp("clps-"),
          CLOUDPANEL_MCP_CONFIG: config,
          CLPCTL_SIM_STATE: join(dir, "sim.json"),
          ...extra,
        },
      }),
    };
  }

  it("writes a private file, checks the connection, and never overwrites", () => {
    const config = join(shortTmp("clpf-"), "sub", "config.json");
    const first = run(["--host", "my-server", "--allow", "write"], config);
    // the fake ssh reaches a host whose clpctl is not at /usr/bin: the check fails, the file is kept
    assert.equal(first.result.status, 1, first.result.stdout + first.result.stderr);
    assert.match(first.result.stdout, /wrote .*config\.json \(mode 600\): profile default, ssh cloudpanel-mcp@my-server, classes: read, write/);
    assert.match(first.result.stdout, /FAILED[\s\S]*hint: /);
    assert.equal(statSync(config).mode & 0o777, 0o600);
    assert.equal(statSync(join(config, "..")).mode & 0o777, 0o700);
    assert.deepEqual(JSON.parse(readFileSync(config, "utf8")).profiles.default.allow, ["write"]);

    const again = run(["--host", "other"], config);
    assert.equal(again.result.status, 2);
    assert.match(again.result.stderr, /already exists and is never overwritten/);
    assert.match(again.result.stderr, /"host": "other"/);
    assert.equal(JSON.parse(readFileSync(config, "utf8")).profiles.default.ssh.host, "my-server");
  });
  it("refuses a value the server would refuse, and writes nothing", () => {
    const config = join(shortTmp("clpf-"), "config.json");
    const r = run(["--host", "bad host;rm"], config).result;
    assert.equal(r.status, 2);
    assert.ok(!existsSync(config));
  });
});
