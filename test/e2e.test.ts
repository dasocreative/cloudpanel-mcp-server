import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { DIST_ENTRY, IS_WINDOWS, installSimClpctl, shortTmp } from "./helpers.ts";
import { RawClient } from "./rawclient.ts";
import type { SimState } from "./sim/clpctl.ts";

/** The real built server over stdio, local transport, the clpctl simulator as the program. */
class Rig {
  readonly dir = shortTmp("clpe-");
  readonly simState = join(this.dir, "sim.json");
  readonly simLog = join(this.dir, "sim.log");
  readonly configPath = join(this.dir, "config.json");
  readonly stateDir = join(this.dir, "state");
  readonly env: Record<string, string>;

  constructor(profile: Record<string, unknown> = {}, extraEnv: Record<string, string> = {}) {
    const clpctl = installSimClpctl(join(this.dir, "bin"));
    mkdirSync(join(this.dir, "files"));
    writeFileSync(
      this.configPath,
      JSON.stringify({
        profiles: {
          test: { local: true, elevation: "none", clpctlPath: clpctl, allow: ["write", "destructive", "admin"], fileDirs: [join(this.dir, "files")], allowUntrustedFileDirs: true, ...profile }, // a temporary directory
        },
      }),
    );
    chmodSync(this.configPath, 0o600);
    this.env = {
      PATH: process.env["PATH"] ?? "/usr/bin:/bin",
      HOME: this.dir,
      CLOUDPANEL_MCP_CONFIG: this.configPath,
      CLOUDPANEL_MCP_STATE_DIR: this.stateDir,
      CLPCTL_SIM_STATE: this.simState,
      CLPCTL_SIM_LOG: this.simLog,
      ...extraEnv,
    };
  }

  state(): SimState {
    return JSON.parse(readFileSync(this.simState, "utf8")) as SimState;
  }

  ranCommands(): string[][] {
    return existsSync(this.simLog)
      ? readFileSync(this.simLog, "utf8").trim().split("\n").filter(Boolean).map((l) => (JSON.parse(l) as { argv: string[] }).argv)
      : [];
  }

  raw(): RawClient {
    return new RawClient(process.execPath, [DIST_ENTRY], this.env);
  }
}

const open: RawClient[] = [];
after(async () => {
  await Promise.all(open.map((c) => c.close()));
});

describe("the real server, 2025-era client written against the wire protocol", { skip: IS_WINDOWS }, () => {
  it("initialises, lists the tools with annotations and the Claude Code metadata, and writes nothing else to stdout", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    const init = await client.initialize({ elicitation: { form: {} } });
    assert.equal(init["result"].serverInfo.name, "cloudpanel-mcp-server");
    assert.match(init["result"].instructions, /untrusted data/);
    const list = (await client.request("tools/list"))["result"].tools as any[];
    const byName = new Map(list.map((t) => [t.name, t]));
    assert.equal(byName.size, 29); // site-user and inventory tools are hidden until a profile configures them
    const del = byName.get("clp_site_delete");
    assert.equal(del.annotations.destructiveHint, true);
    assert.equal(del.annotations.readOnlyHint, false);
    assert.equal(del._meta["anthropic/requiresUserInteraction"], true);
    assert.equal(byName.get("clp_user_list")._meta, undefined);
    assert.equal(byName.get("clp_user_list").annotations.readOnlyHint, true);
    assert.equal(byName.get("clp_site_add_php")._meta, undefined);
    for (const tool of list) {
      assert.equal(tool.inputSchema.additionalProperties, false, tool.name);
      assert.ok(!("confirm" in tool.inputSchema.properties), `${tool.name} must not take a confirm parameter`);
      assert.ok(!Object.keys(tool.inputSchema.properties).some((k) => /pass/i.test(k)), `${tool.name} must not take a password`);
      assert.match(tool.description, /untrusted data|Class READ/);
    }
    assert.deepEqual(client.stdoutNonJson, []);
  });

  it("deletes a site only after the human types the name in the form the server sent", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    await client.initialize({ elicitation: { form: {} } });
    client.onServerRequest = (m) => {
      assert.equal(m["method"], "elicitation/create");
      assert.equal(m["params"].mode, "form");
      const props = m["params"].requestedSchema.properties;
      if (props.approve !== undefined) return { action: "accept", content: { approve: true } };
      assert.match(m["params"].message, /DESTRUCTIVE/);
      assert.match(m["params"].message, /type the domain name exactly: old\.example\.com/);
      return { action: "accept", content: { typed: "old.example.com" } };
    };
    const ok = await client.callTool("clp_site_add_static", { domainName: "old.example.com", siteUser: "old" });
    assert.equal(ok.isError, false, JSON.stringify(ok.body));
    assert.equal(rig.state().sites.length, 1);

    const plan = await client.callTool("clp_site_delete", { domainName: "old.example.com" });
    assert.equal(plan.isError, false);
    assert.equal(plan.body.nothingWasRun, true);
    assert.equal(rig.state().sites.length, 1);
    const deleted = await client.callTool("clp_site_delete", { domainName: "old.example.com", planToken: plan.body.planToken });
    assert.equal(deleted.isError, false, JSON.stringify(deleted.body));
    assert.equal(rig.state().sites.length, 0);
    assert.ok(rig.ranCommands().some((a) => a[0] === "site:delete" && a.includes("--force")));
  });

  it("refuses a wrong typed name and a decline; the site stays", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    await client.initialize({ elicitation: { form: {} } });
    client.onServerRequest = () => ({ action: "accept", content: { approve: true } });
    await client.callTool("clp_site_add_static", { domainName: "keep.example.com", siteUser: "keep" });
    for (const answer of [{ action: "accept", content: { typed: "nope.example.com" } }, { action: "decline" }, { action: "cancel" }]) {
      client.onServerRequest = () => answer;
      const plan = await client.callTool("clp_site_delete", { domainName: "keep.example.com" });
      const out = await client.callTool("clp_site_delete", { domainName: "keep.example.com", planToken: plan.body.planToken });
      assert.equal(out.isError, true, JSON.stringify(answer));
    }
    assert.equal(rig.state().sites.length, 1);
    const audit = readFileSync(join(rig.stateDir, "audit.jsonl"), "utf8");
    assert.match(audit, /"decision":"mismatch"/);
    assert.match(audit, /"decision":"decline"/);
    assert.match(audit, /"decision":"cancel"/);
  });

  it("a client without the elicitation capability gets the exact command and nothing runs", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    await client.initialize({});
    const plan = await client.callTool("clp_site_delete", { domainName: "x.example.com" });
    const out = await client.callTool("clp_site_delete", { domainName: "x.example.com", planToken: plan.body.planToken });
    assert.equal(out.isError, true);
    assert.equal(out.body.decision, "unsupported");
    assert.match(out.body.manualCommand, /site:delete/);
    assert.equal(client.serverRequests.length, 0);
    assert.ok(!rig.ranCommands().some((a) => a[0] === "site:delete"));
  });

  it("a form-only client (bare elicitation capability) is asked", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    await client.initialize({ elicitation: {} });
    client.onServerRequest = () => ({ action: "accept", content: { approve: true } });
    const out = await client.callTool("clp_site_add_static", { domainName: "bare.example.com", siteUser: "bare" });
    assert.equal(out.isError, false, JSON.stringify(out.body));
    assert.equal(client.serverRequests.length, 1);
  });

  it("returns tool errors as results, not as protocol errors, for hostile input", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    await client.initialize({ elicitation: { form: {} } });
    for (const args of [
      { domainName: "a.example.com; rm -rf /", siteUser: "x" },
      { domainName: "a.example.com", siteUser: "x", extra: 1 },
      { domainName: "a.example.com", siteUser: "-rf" },
      { domainName: ["a.example.com"], siteUser: "x" },
      { siteUser: "x" },
      {},
    ]) {
      const out = await client.callTool("clp_site_add_static", args);
      assert.equal(out.isError, true, JSON.stringify(args));
      assert.equal(out.body.refused, true);
    }
    const unknown = await client.callTool("clp_raw_command", { command: "id" });
    assert.equal(unknown.isError, true);
    assert.deepEqual(rig.ranCommands().filter((a) => a.length > 0 && a[0] !== undefined), []);
  });

  it("never prints a generated password on stdout or stderr or in the audit log", async () => {
    const rig = new Rig();
    const client = rig.raw();
    open.push(client);
    await client.initialize({ elicitation: { form: {} } });
    client.onServerRequest = () => ({ action: "accept", content: { approve: true } });
    const out = await client.callTool("clp_site_add_static", { domainName: "pw.example.com", siteUser: "pw" });
    assert.equal(out.isError, false, JSON.stringify(out.body));
    const password = rig.state().sites[0]?.password as string;
    assert.match(password, /^[A-Za-z0-9]{32}$/);
    assert.ok(!JSON.stringify(out.raw).includes(password));
    assert.ok(!client.stderr.includes(password));
    assert.ok(!readFileSync(join(rig.stateDir, "audit.jsonl"), "utf8").includes(password));
    assert.ok(readFileSync(out.body.secretsFile, "utf8").includes(password));
  });
});

describe("the real server, 2026-era and 2025-era clients written with the v2 SDK", { skip: IS_WINDOWS }, () => {
  for (const mode of ["legacy", "auto", "modern"] as const) {
    it(`deletes after a typed confirmation (client mode ${mode})`, async () => {
      const rig = new Rig();
      const client = new Client(
        { name: "sdk-test-client", version: "0.0.0" },
        {
          capabilities: { elicitation: { form: {} } },
          ...(mode === "legacy" ? {} : { versionNegotiation: { mode: mode === "auto" ? "auto" : { pin: "2026-07-28" } } }),
        } as never,
      );
      const asked: string[] = [];
      client.setRequestHandler("elicitation/create", async (request: any) => {
        asked.push(request.params.message);
        return request.params.requestedSchema.properties.approve !== undefined
          ? { action: "accept", content: { approve: true } }
          : { action: "accept", content: { typed: "sdk.example.com" } };
      });
      await client.connect(new StdioClientTransport({ command: process.execPath, args: [DIST_ENTRY], env: rig.env, stderr: "pipe" }));
      try {
        if (mode === "modern") assert.equal(client.getProtocolEra(), "modern");
        const tools = await client.listTools();
        assert.equal((tools.tools.find((t) => t.name === "clp_site_delete") as any)._meta["anthropic/requiresUserInteraction"], true);
        const added: any = await client.callTool({ name: "clp_site_add_static", arguments: { domainName: "sdk.example.com", siteUser: "sdk" } });
        assert.ok(!added.isError, JSON.stringify(added));
        const plan: any = await client.callTool({ name: "clp_site_delete", arguments: { domainName: "sdk.example.com" } });
        const token = JSON.parse(plan.content[0].text).planToken as string;
        const gone: any = await client.callTool({ name: "clp_site_delete", arguments: { domainName: "sdk.example.com", planToken: token } });
        assert.ok(!gone.isError, JSON.stringify(gone));
        assert.equal(rig.state().sites.length, 0);
        assert.equal(asked.length, 2);
        assert.match(asked[1] as string, /DESTRUCTIVE/);
      } finally {
        await client.close();
      }
    });
  }

  it("2026 era without the capability is refused with the manual command, not a protocol error", async () => {
    const rig = new Rig();
    const client = new Client({ name: "sdk-test-client", version: "0.0.0" }, { capabilities: {}, versionNegotiation: { mode: { pin: "2026-07-28" } } } as never);
    await client.connect(new StdioClientTransport({ command: process.execPath, args: [DIST_ENTRY], env: rig.env, stderr: "pipe" }));
    try {
      const plan: any = await client.callTool({ name: "clp_site_delete", arguments: { domainName: "x.example.com" } });
      const token = JSON.parse(plan.content[0].text).planToken as string;
      const out: any = await client.callTool({ name: "clp_site_delete", arguments: { domainName: "x.example.com", planToken: token } });
      assert.equal(out.isError, true);
      assert.equal(JSON.parse(out.content[0].text).decision, "unsupported");
    } finally {
      await client.close();
    }
  });
});
