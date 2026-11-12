import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { diagnose, checkConnection } from "../src/doctor.ts";
import { defaultTransports } from "../src/exec/transport.ts";
import { bundleServerSetup } from "../src/setup.ts";
import { buildApprovalRequest, evaluateDecision } from "../src/policy/approval.ts";
import { DIST_ENTRY, IS_WINDOWS, ROOT, SIM_DIR, installSimClpctl, makeProfile, okResult, shortTmp } from "./helpers.ts";

const SETUP = readFileSync(join(ROOT, "hardening", "cloudpanel-mcp-setup.sh"), "utf8");
const GATE = readFileSync(join(ROOT, "hardening", "cloudpanel-mcp-gate.sh"), "utf8");
const INVENTORY = readFileSync(join(ROOT, "inventory", "cloudpanel-mcp-inventory"), "utf8");

describe("--print-server-setup bundle", () => {
  const bundle = bundleServerSetup(SETUP, GATE, INVENTORY, "1.2.3");

  it("embeds the gate and the inventory of the same release, byte for byte", () => {
    const gate = /embedded_gate\(\) \{\n {2}cat <<'CLOUDPANEL_MCP_GATE_EOF'\n([\s\S]*?)CLOUDPANEL_MCP_GATE_EOF\n\}/.exec(bundle);
    const inventory = /embedded_inventory\(\) \{\n {2}cat <<'CLOUDPANEL_MCP_INVENTORY_EOF'\n([\s\S]*?)CLOUDPANEL_MCP_INVENTORY_EOF\n\}/.exec(bundle);
    assert.equal(gate?.[1], GATE);
    assert.equal(inventory?.[1], INVENTORY);
    assert.ok(!bundle.includes("embedded_gate() { return 1; }"));
  });
  it("pins the version it was printed by, and only a version-shaped one", () => {
    assert.match(bundle, /cloudpanel-mcp-server@1\.2\.3 --init --host/);
    assert.match(bundle, /cloudpanel-mcp-server@1\.2\.3 --print-server-setup/);
    assert.ok(!bundle.includes("@<version>"));
    assert.match(bundleServerSetup(SETUP, GATE, INVENTORY, "1.2.3; rm -rf /"), /cloudpanel-mcp-server@<version>/);
  });
  it("calls main only after every function is defined, so a script read from stdin runs whole or not at all", () => {
    const lines = bundle.trimEnd().split("\n");
    assert.equal(lines.at(-1), 'main "$@"');
    assert.ok(bundle.indexOf('main "$@"') > bundle.indexOf("CLOUDPANEL_MCP_INVENTORY_EOF\n}"));
    assert.match(bundle, /exec <\/dev\/null/);
  });
  it("refuses a file that contains its own heredoc terminator", () => {
    assert.throws(() => bundleServerSetup(SETUP, "x\nCLOUDPANEL_MCP_GATE_EOF\ny", INVENTORY, "1.0.0"), /terminator/);
    assert.throws(() => bundleServerSetup("no markers", GATE, INVENTORY, "1.0.0"), /embedded block/);
  });
  it("parses with bash, and its embedded gate is the gate", { skip: IS_WINDOWS }, () => {
    const syntax = spawnSync("bash", ["-n"], { input: bundle, encoding: "utf8" });
    assert.equal(syntax.status, 0, syntax.stderr);
    const extracted = spawnSync("bash", ["-c", `${bundle.replace(/\nmain "\$@"\n?$/, "\n")}\nembedded_gate`], { encoding: "utf8" });
    assert.equal(extracted.status, 0, extracted.stderr);
    assert.equal(extracted.stdout, GATE);
  });
  it("prints its help and refuses bad options without touching anything", { skip: IS_WINDOWS }, () => {
    const help = spawnSync("bash", ["-s", "--", "--help"], { input: bundle, encoding: "utf8" });
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /--allow <level>/);
    const bad = spawnSync("bash", ["-s", "--", "--allow", "everything"], { input: bundle, encoding: "utf8" });
    assert.notEqual(bad.status, 0);
    const unknown = spawnSync("bash", ["-s", "--", "--frobnicate"], { input: bundle, encoding: "utf8" });
    assert.notEqual(unknown.status, 0);
    assert.match(unknown.stderr, /unknown option/);
  });
});

describe("--check-connection diagnosis", () => {
  const ssh = makeProfile({ target: { kind: "ssh", ssh: { host: "my-server", user: "cloudpanel-mcp", identityFile: "/k/id" } } } as never);
  const failed = (stderr: string, over: Record<string, unknown> = {}) => okResult({ exitCode: 255, stderr, stdout: "", ...over });

  for (const [stderr, hint] of [
    ["Host key verification failed.", /host key is not known.*ssh -i \/k\/id cloudpanel-mcp@my-server/],
    ["cloudpanel-mcp@my-server: Permission denied (publickey).", /refused the key.*AllowUsers/],
    ["ssh: Could not resolve hostname my-server: nodename nor servname provided", /does not resolve/],
    ["ssh: connect to host my-server port 22: Connection refused", /cannot be reached/],
    ["sudo: a password is required", /sudoers line/],
    ["cloudpanel-mcp-gate: refused: unknown command", /gate on the server refused/],
    ["Sorry, user cloudpanel-mcp is not allowed to execute '/usr/bin/clpctl' as root", /may not run/],
  ] as const) {
    it(`explains: ${stderr}`, () => assert.match(diagnose(failed(stderr), ssh), hint));
  }
  it("explains a timeout as a prompt nobody can answer", () => {
    assert.match(diagnose(okResult({ exitCode: null, timedOut: true, stdout: "", stderr: "" }), ssh), /prompt nobody can answer/);
  });
  it("explains a missing clpctl", () => {
    assert.match(diagnose(okResult({ exitCode: 127, stdout: "", stderr: "bash: /usr/bin/clpctl: No such file or directory" }), ssh), /CLOUDPANEL_MCP_CLPCTL_PATH/);
  });
});

describe("--check-connection over (fake) ssh", { skip: IS_WINDOWS }, () => {
  function rig() {
    const dir = shortTmp("clpd-");
    const clpctl = installSimClpctl(join(dir, "bin"));
    const saved = { PATH: process.env["PATH"], CLPCTL_SIM_STATE: process.env["CLPCTL_SIM_STATE"], FAKE_SSH_FAIL: process.env["FAKE_SSH_FAIL"] };
    process.env["PATH"] = `${join(SIM_DIR, "bin")}:${saved.PATH ?? ""}`;
    process.env["CLPCTL_SIM_STATE"] = join(dir, "sim.json");
    const restore = () => {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    };
    const profile = makeProfile({ target: { kind: "ssh", ssh: { host: "my-server" } }, elevation: "sudo", clpctlPath: clpctl } as never);
    return { dir, profile, restore };
  }

  it("says ok and how many commands clpctl offers", async () => {
    const r = rig();
    try {
      const report = await checkConnection(r.profile, defaultTransports(r.dir, "linux"));
      assert.equal(report.ok, true, report.lines.join("\n"));
      assert.match(report.lines[0] as string, /: ok - sudo -n .*clpctl answered with \d+ commands/);
    } finally {
      r.restore();
    }
  });
  it("says FAILED, shows what ssh printed and gives a hint", async () => {
    const r = rig();
    try {
      process.env["FAKE_SSH_FAIL"] = "1";
      const report = await checkConnection(r.profile, defaultTransports(r.dir, "linux"));
      assert.equal(report.ok, false);
      const text = report.lines.join("\n");
      assert.match(text, /FAILED \(exit status 255\)/);
      assert.match(text, /\| ssh: connect to host my-server port 22: Connection refused/);
      assert.match(text, /hint: the server cannot be reached/);
    } finally {
      r.restore();
    }
  });
});

describe("CLI: --print-server-setup and --check-connection", { skip: !existsSync(DIST_ENTRY) || IS_WINDOWS }, () => {
  const env = (extra: Record<string, string>) => ({
    PATH: `${join(SIM_DIR, "bin")}:${process.env["PATH"] ?? "/usr/bin:/bin"}`,
    HOME: shortTmp("clph-"),
    CLOUDPANEL_MCP_STATE_DIR: shortTmp("clps-"),
    ...extra,
  });

  it("--print-server-setup needs no configuration and prints a script that parses", () => {
    const r = spawnSync(process.execPath, [DIST_ENTRY, "--print-server-setup"], { encoding: "utf8", env: env({}) });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^#!\/bin\/bash\n# cloudpanel-mcp-setup\.sh/);
    assert.ok(r.stdout.includes(GATE));
    assert.equal(spawnSync("bash", ["-n"], { input: r.stdout, encoding: "utf8" }).status, 0);
  });
  it("--check-connection exits 0 when every profile answers, 1 otherwise", () => {
    const dir = shortTmp("clpc-");
    const clpctl = installSimClpctl(join(dir, "bin"));
    const base = { CLOUDPANEL_MCP_SSH_HOST: "my-server", CLOUDPANEL_MCP_CLPCTL_PATH: clpctl, CLPCTL_SIM_STATE: join(dir, "sim.json") };
    const ok = spawnSync(process.execPath, [DIST_ENTRY, "--check-connection"], { encoding: "utf8", env: env(base) });
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /ok - sudo -n /);
    const bad = spawnSync(process.execPath, [DIST_ENTRY, "--check-connection"], { encoding: "utf8", env: env({ ...base, FAKE_SSH_FAIL: "1" }) });
    assert.equal(bad.status, 1, bad.stdout + bad.stderr);
    assert.match(bad.stdout, /hint: /);
  });
});

describe("approval forms that every client with forms can show", () => {
  const base = { key: "k", profile: "p", summary: "s", command: "clpctl x", effects: ["e"], reversible: "no" };
  for (const request of [
    buildApprovalRequest({ ...base, cls: "write" }),
    buildApprovalRequest({ ...base, cls: "destructive", target: "shop.example.com", noun: "domain" }),
  ]) {
    it(`${request.kind}: no top-level title or description (Codex cancels such a form), a required field, nothing pre-approved`, () => {
      const schema = request.requestedSchema as unknown as Record<string, unknown>;
      assert.deepEqual(Object.keys(schema).sort(), ["properties", "required", "type"]);
      assert.ok(request.requestedSchema.required.length > 0);
      for (const field of request.requestedSchema.required) {
        const prop = request.requestedSchema.properties[field] as Record<string, unknown>;
        assert.ok(prop["default"] === undefined || prop["default"] === false, `${field} must not default to an approval`);
      }
      // an empty accept (what some clients send for a form they did not show) is refused
      assert.equal(evaluateDecision(request, { action: "accept", content: {} }).approved, false);
      assert.equal(evaluateDecision(request, { action: "accept" }).approved, false);
    });
  }
});
