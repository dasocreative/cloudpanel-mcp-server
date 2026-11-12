import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { buildCatalog } from "../src/catalog/index.ts";
import type { CommandPlan, ToolSpec } from "../src/catalog/define.ts";
import { NeedInput } from "../src/engine.ts";
import {
  FIXED_PASSWORD,
  FakeIO,
  IS_WINDOWS,
  SimTransport,
  approve,
  bodyOf,
  makeHarness,
  makeProfile,
  noHuman,
  okResult,
} from "./helpers.ts";

const ADD_STATIC = { domainName: "shop.example.com", siteUser: "shop" };

function secretFiles(stateDir: string): string[] {
  const dir = join(stateDir, "secrets", "test");
  return existsSync(dir) ? readdirSync(dir).map((f) => join(dir, f)) : [];
}

describe("read tools", () => {
  it("run without asking anybody and parse the table", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    const out = await h.call("clp_user_list", {}, noHuman);
    assert.equal(out.isError, false);
    assert.equal(bodyOf(out).output.table.headers[0], "User Name");
    assert.equal(bodyOf(out).output.table.rows[0][0], "admin");
    assert.equal(h.transport.calls.length, 2); // the probe and the command
  });

  it("are listed when no changing class is enabled, changing tools are not", () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    const names = h.engine.toolNames;
    assert.ok(names.includes("clp_user_list"));
    assert.ok(names.includes("clp_server_info"));
    assert.ok(!names.includes("clp_site_add_static"));
    assert.ok(!names.includes("clp_site_delete"));
    assert.ok(!names.includes("clp_user_add"));
  });
});

describe("class gate", () => {
  it("lists exactly the classes a profile allows", () => {
    const h = makeHarness({ profile: { allow: new Set(["write"]) } });
    assert.ok(h.engine.toolNames.includes("clp_site_add_static"));
    assert.ok(!h.engine.toolNames.includes("clp_site_delete"));
    assert.ok(!h.engine.toolNames.includes("clp_user_add"));
  });

  it("refuses a forced call to a tool whose class is off, and runs nothing", async () => {
    const h = makeHarness({ profile: { allow: new Set(["write"]) } });
    const out = await h.call("clp_site_delete", { domainName: "a.example.com" }, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).refused, true);
    assert.equal(h.transport.calls.length, 0);
  });
});

describe("write tools", () => {
  it("dryRun returns the exact redacted command and runs nothing", async () => {
    const h = makeHarness();
    const io = new FakeIO(approve);
    const out = await h.call("clp_site_add_static", { ...ADD_STATIC, dryRun: true }, io);
    assert.equal(out.isError, false);
    const body = bodyOf(out);
    assert.equal(body.nothingWasRun, true);
    assert.match(body.plan.command, /site:add:static/);
    assert.match(body.plan.command, /--siteUserPassword=\[REDACTED\]/);
    assert.ok(!h.transport.calls.some((c) => c.argv.includes("site:add:static"))); // only the read-only probe ran
    assert.equal(io.asked.length, 0);
    assert.equal(typeof body.planToken, "string");
  });

  it("asks the human with a tick box, then runs and saves the password to a 0600 file", async () => {
    const h = makeHarness();
    const io = new FakeIO(approve);
    const out = await h.call("clp_site_add_static", ADD_STATIC, io);
    const body = bodyOf(out);
    assert.equal(out.isError, false, JSON.stringify(body));
    assert.equal(io.asked.length, 1);
    assert.equal(io.asked[0]?.kind, "confirm-box");
    assert.match(io.asked[0]?.message ?? "", /Command run on the server:/);
    assert.equal(h.transport.state.sites.length, 1);
    // the password reached clpctl, was stored, and appears nowhere in the result or the audit log
    assert.equal(h.transport.state.sites[0]?.password, FIXED_PASSWORD);
    const files = secretFiles(h.stateDir);
    assert.equal(files.length, 1);
    if (!IS_WINDOWS) assert.equal(statSync(files[0] as string).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(files[0] as string, "utf8")).password, FIXED_PASSWORD);
    assert.equal(body.secretsFile, files[0]);
    assert.ok(!JSON.stringify(body).includes(FIXED_PASSWORD));
    assert.ok(!readFileSync(h.auditPath, "utf8").includes(FIXED_PASSWORD));
  });

  it("refuses when the human declines, cancels, times out or ticks nothing; nothing runs", async () => {
    for (const answer of [
      { action: "decline" as const },
      { action: "cancel" as const },
      { action: "timeout" as const },
      { action: "error" as const, detail: "x" },
      { action: "accept" as const, content: { approve: false } },
      { action: "accept" as const, content: {} },
      { action: "accept" as const },
    ]) {
      const h = makeHarness();
      const out = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(answer));
      assert.equal(out.isError, true, JSON.stringify(answer));
      assert.equal(h.transport.state.sites.length, 0);
      assert.equal(h.transport.calls.filter((c) => c.argv.includes("site:add:static")).length, 0);
      assert.ok(h.audit().some((e) => e["event"] === "approval" && e["decision"] !== "accept"));
    }
  });

  it("refuses with the exact command when the client cannot show a form", async () => {
    const h = makeHarness();
    const out = await h.call("clp_site_add_static", ADD_STATIC, noHuman);
    const body = bodyOf(out);
    assert.equal(out.isError, true);
    assert.equal(body.decision, "unsupported");
    assert.match(body.manualCommand, /site:add:static/);
    assert.match(body.manualCommand, /<choose a strong password>/);
    assert.equal(h.transport.state.sites.length, 0);
    assert.ok(h.audit().some((e) => e["decision"] === "unsupported"));
  });

  it("with approval.write=client runs without a form and audits that", async () => {
    const h = makeHarness({ profile: { approvalWrite: "client" } });
    const out = await h.call("clp_site_add_static", ADD_STATIC, noHuman);
    assert.equal(out.isError, false, JSON.stringify(bodyOf(out)));
    assert.equal(h.transport.state.sites.length, 1);
    assert.ok(h.audit().some((e) => e["decision"] === "not-required"));
  });

  it("a model-supplied password is refused before anything else", async () => {
    const h = makeHarness();
    for (const key of ["password", "siteUserPassword", "databaseUserPassword", "Passwd"]) {
      const out = await h.call("clp_site_add_static", { ...ADD_STATIC, [key]: "hunter22hunter22" }, new FakeIO(approve));
      assert.equal(out.isError, true);
      assert.match(bodyOf(out).reason, /passwords are never parameters/);
    }
    assert.equal(h.transport.calls.length, 0);
  });

  it("moves the password file aside when the command fails", async () => {
    const h = makeHarness();
    h.transport.state.sites.push({ domain: "shop.example.com", type: "static", siteUser: "other", password: "x" });
    const out = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).output.serverMessage, /already exists/);
    assert.equal(bodyOf(out).error, undefined);
    const files = secretFiles(h.stateDir);
    assert.equal(files.length, 1);
    assert.match(files[0] as string, /\.failed\.json$/);
    assert.match(bodyOf(out).passwordNote, /never applied/);
  });
});

describe("destructive tools", () => {
  const seed = (h: ReturnType<typeof makeHarness>): void => {
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
  };

  it("the first call returns a plan and a token and runs nothing", async () => {
    const h = makeHarness();
    seed(h);
    const io = new FakeIO(approve);
    const out = await h.call("clp_site_delete", { domainName: "old.example.com" }, io);
    const body = bodyOf(out);
    assert.equal(out.isError, false);
    assert.equal(body.nothingWasRun, true);
    assert.equal(typeof body.planToken, "string");
    assert.match(body.plan.approval, /must type the domain "old.example.com"/);
    assert.equal(h.transport.state.sites.length, 1);
    assert.equal(io.asked.length, 0);
  });

  it("deletes only after the human TYPES the name; the token is single use", async () => {
    const h = makeHarness();
    seed(h);
    const io = new FakeIO(approve);
    const plan = bodyOf(await h.call("clp_site_delete", { domainName: "old.example.com" }, io));
    const out = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: plan.planToken }, io);
    assert.equal(out.isError, false, JSON.stringify(bodyOf(out)));
    assert.equal(io.asked[0]?.kind, "type-target");
    assert.equal(h.transport.state.sites.length, 0);
    assert.ok(h.transport.calls.some((c) => c.argv.includes("--force")));
    const again = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: plan.planToken }, io);
    assert.equal(again.isError, true);
    assert.match(bodyOf(again).reason, /already used/);
  });

  it("refuses a wrong typed name, a decline, and everything but an explicit accept", async () => {
    for (const answer of [
      { action: "accept" as const, content: { typed: "other.example.com" } },
      { action: "accept" as const, content: { typed: "old.example.com " } },
      { action: "accept" as const, content: { typed: "OLD.example.com" } },
      { action: "accept" as const, content: { typed: "" } },
      { action: "accept" as const, content: { approve: true } },
      { action: "accept" as const, content: { typed: ["old.example.com"] } },
      { action: "decline" as const },
      { action: "cancel" as const },
      { action: "timeout" as const },
    ]) {
      const h = makeHarness();
      seed(h);
      const plan = bodyOf(await h.call("clp_site_delete", { domainName: "old.example.com" }, new FakeIO(approve)));
      const out = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: plan.planToken }, new FakeIO(answer as never));
      assert.equal(out.isError, true, JSON.stringify(answer));
      assert.equal(h.transport.state.sites.length, 1, JSON.stringify(answer));
    }
  });

  it("a token for another target or profile is useless", async () => {
    const h = makeHarness();
    seed(h);
    h.transport.state.sites.push({ domain: "keep.example.com", type: "static", siteUser: "keep", password: "x" });
    const plan = bodyOf(await h.call("clp_site_delete", { domainName: "old.example.com" }, new FakeIO(approve)));
    const io = new FakeIO(approve);
    const out = await h.call("clp_site_delete", { domainName: "keep.example.com", planToken: plan.planToken }, io);
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).reason, /does not belong/);
    assert.equal(h.transport.state.sites.length, 2);
    assert.equal(io.asked.length, 0, "the human is not asked about a call whose token is no good");
  });

  it("an expired token is refused", async () => {
    let now = 1_700_000_000_000;
    const h = makeHarness({ now: () => now });
    seed(h);
    const plan = bodyOf(await h.call("clp_site_delete", { domainName: "old.example.com" }, new FakeIO(approve)));
    now += 11 * 60_000;
    const io = new FakeIO(approve);
    const out = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: plan.planToken }, io);
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).reason, /expired/);
    assert.equal(io.asked.length, 0, "the human is not asked about a call whose token is no good");
  });

  it("refuses protected domains, with or without www", async () => {
    const h = makeHarness({ profile: { protect: { domains: ["panel.example.com", "*.prod.example.com"], siteUsers: [], databases: [], panelUsers: [] } } });
    for (const d of ["panel.example.com", "www.panel.example.com", "a.prod.example.com", "prod.example.com"]) {
      const out = await h.call("clp_site_delete", { domainName: d }, new FakeIO(approve));
      assert.equal(out.isError, true, d);
      assert.match(bodyOf(out).reason, /protected/);
    }
  });

  it("cannot approve through a client without elicitation", async () => {
    const h = makeHarness();
    seed(h);
    const plan = bodyOf(await h.call("clp_site_delete", { domainName: "old.example.com" }, noHuman));
    const out = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: plan.planToken }, noHuman);
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).decision, "unsupported");
    assert.match(bodyOf(out).manualCommand, /site:delete/);
    assert.equal(h.transport.state.sites.length, 1);
  });

  it("2026 era: the first entry needs input (nothing changed), the retry with the answer deletes", async () => {
    const h = makeHarness();
    seed(h);
    const plan = bodyOf(await h.call("clp_site_delete", { domainName: "old.example.com" }, new FakeIO(approve)));
    const args = { domainName: "old.example.com", planToken: plan.planToken };
    await assert.rejects(h.call("clp_site_delete", args, new FakeIO(undefined)), NeedInput);
    assert.equal(h.transport.state.sites.length, 1);
    const out = await h.call("clp_site_delete", args, new FakeIO(approve));
    assert.equal(out.isError, false);
    assert.equal(h.transport.state.sites.length, 0);
  });

  it("rate limits destructive calls", async () => {
    const h = makeHarness();
    let done = 0;
    for (let i = 0; i < 5; i += 1) {
      h.transport.state.sites.push({ domain: `s${i}.example.com`, type: "static", siteUser: `s${i}`, password: "x" });
      const out = await h.apply("clp_site_delete", { domainName: `s${i}.example.com` }, new FakeIO(approve));
      if (!out.isError) done += 1;
      else assert.match(bodyOf(out).reason, /rate limit/);
    }
    assert.equal(done, 3);
  });

  it("does not even ask the human once the limit is reached", async () => {
    const h = makeHarness();
    for (let i = 0; i < 3; i += 1) {
      h.transport.state.sites.push({ domain: `s${i}.example.com`, type: "static", siteUser: `s${i}`, password: "x" });
      assert.equal((await h.apply("clp_site_delete", { domainName: `s${i}.example.com` }, new FakeIO(approve))).isError, false);
    }
    h.transport.state.sites.push({ domain: "s9.example.com", type: "static", siteUser: "s9", password: "x" });
    const io = new FakeIO(approve);
    const out = await h.apply("clp_site_delete", { domainName: "s9.example.com" }, io);
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).reason, /rate limit/);
    assert.equal(io.asked.length, 0);
  });
});

describe("admin tools", () => {
  it("add a panel user: typed name, generated password in a file", async () => {
    const h = makeHarness();
    const io = new FakeIO(approve);
    const out = await h.apply(
      "clp_user_add",
      { userName: "jane", email: "jane@example.com", firstName: "Jane", lastName: "Doe", role: "admin", timezone: "UTC", status: "1" },
      io,
    );
    assert.equal(out.isError, false, JSON.stringify(bodyOf(out)));
    assert.equal(io.asked[0]?.kind, "type-target");
    assert.equal(io.asked[0]?.target, "jane");
    assert.ok(h.transport.state.users.some((u) => u.userName === "jane" && u.password === FIXED_PASSWORD));
    assert.ok(!JSON.stringify(bodyOf(out)).includes(FIXED_PASSWORD));
  });

  it("protected panel users cannot be deleted, reset or have MFA disabled", async () => {
    const h = makeHarness({ profile: { protect: { domains: [], siteUsers: [], databases: [], panelUsers: ["admin"] } } });
    for (const tool of ["clp_user_delete", "clp_user_reset_password", "clp_user_disable_mfa"]) {
      const out = await h.call(tool, { userName: "admin" }, new FakeIO(approve));
      assert.equal(out.isError, true, tool);
      assert.match(bodyOf(out).reason, /protected/);
    }
  });

  it("the master credentials never reach the result", async () => {
    const h = makeHarness();
    const out = await h.apply("clp_db_show_master_credentials", {}, new FakeIO(approve));
    const text = JSON.stringify(bodyOf(out));
    assert.equal(out.isError, false, text);
    assert.ok(!text.includes("SIM-MASTER-PASSWORD"));
    const file = bodyOf(out).secretsFile as string;
    assert.ok(readFileSync(file, "utf8").includes("SIM-MASTER-PASSWORD"));
    if (!IS_WINDOWS) assert.equal(statSync(file).mode & 0o777, 0o600);
  });
});

describe("failure handling", () => {
  it("reports an exit status of 0 with an error log line as a failure", async () => {
    const t = new SimTransport(undefined, { errorExitCode: 0 });
    const h = makeHarness({ transport: t });
    t.state.sites.push({ domain: "shop.example.com", type: "static", siteUser: "other", password: "x" });
    const out = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).note, /error log line/);
  });

  it("reports a timeout and says the command may still run", async () => {
    const t = new SimTransport();
    t.override = (request) => (request.argv.includes("site:add:static") ? okResult({ exitCode: null, timedOut: true }) : undefined);
    const h = makeHarness({ transport: t });
    const out = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).timedOut, true);
    assert.match(bodyOf(out).note, /may still be running/);
  });

  it("does not run a changing command when the audit log cannot be written", async () => {
    const h = makeHarness();
    // a directory where the audit file should be: appending fails
    mkdirSync(join(h.stateDir, "audit.jsonl"));
    const out = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).reason, /audit log could not be written/);
    assert.equal(h.transport.state.sites.length, 0);
    assert.equal(secretFiles(h.stateDir).length, 0); // the reserved password file was removed again
  });
});

describe("availability from the usage listing", () => {
  it("refuses a tool whose command the server does not list", async () => {
    const t = new SimTransport();
    t.override = (request) =>
      request.argv.length === 1
        ? okResult({ stdout: " clpctl user:list\n clpctl site:add:static --domainName=a.com --siteUser=x --siteUserPassword=y\n" })
        : undefined;
    const h = makeHarness({ transport: t });
    const out = await h.call("clp_db_delete", { databaseName: "x" }, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).reason, /does not list the command db:delete/);
  });

  it("refuses a tool when a required option is not shown, but not for a missing optional one", async () => {
    const t = new SimTransport();
    t.override = (request) =>
      request.argv.length === 1
        ? okResult({ stdout: " clpctl site:add:static --domainName=a.com --siteUser=x\n clpctl site:delete --domainName=a.com\n" })
        : undefined;
    const h = makeHarness({ transport: t });
    const add = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(approve));
    assert.equal(add.isError, true);
    assert.match(bodyOf(add).reason, /without the option --siteUserPassword/);
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    const del = await h.apply("clp_site_delete", { domainName: "old.example.com" }, new FakeIO(approve));
    assert.equal(del.isError, false, JSON.stringify(bodyOf(del))); // --force is not in the usage line and that is fine
  });

  it("does not block when the probe fails or cannot be parsed", async () => {
    const t = new SimTransport();
    let probes = 0;
    t.override = (request) => {
      if (request.argv.length === 1) {
        probes += 1;
        return okResult({ stdout: "something else entirely\n" });
      }
      return undefined;
    };
    const h = makeHarness({ transport: t });
    const out = await h.call("clp_user_list", {}, noHuman);
    assert.equal(out.isError, false);
    assert.equal(probes, 1);
  });
});

describe("server info", () => {
  it("shows the profile, the classes and whether this client can approve", async () => {
    const h = makeHarness({ profile: { allow: new Set(["write"]), name: "test" } });
    const out = await h.call("clp_server_info", {}, noHuman);
    const body = bodyOf(out);
    assert.equal(out.isError, false);
    assert.equal(body.client.canShowApprovalForms, false);
    assert.deepEqual(body.profiles[0].allowedClasses, ["read", "write"]);
    assert.equal(body.detection.status, "ok");
    assert.equal(body.detection.commandCount, 28);
  });

  it("clp_list_commands compares with the documented set", async () => {
    const h = makeHarness();
    const out = await h.call("clp_list_commands", {}, noHuman);
    const body = bodyOf(out);
    assert.equal(out.isError, false);
    assert.match(body.output.untrusted, /comes from the server/);
    assert.equal(body.output.commandsOnServer.length, 28);
    assert.deepEqual(body.documentedCommandsMissingOnServer, []);
    assert.deepEqual(body.siteUserCommandsNotInRootListing, ["varnish-cache:purge"]);
    assert.deepEqual(body.output.commandsOnServerWithoutATool, []);
    assert.equal(body.commandsOnServer, undefined, "names the server chose are inside `output` only");
    assert.equal(body.optionDifferences, undefined);
  });
});

describe("profiles", () => {
  it("require an explicit profile when several exist and refuse an unknown one", async () => {
    const a = makeProfile({ name: "alpha" });
    const b = makeProfile({ name: "beta", allow: new Set() });
    const h = makeHarness({ profiles: [a, b] });
    const missing = await h.call("clp_user_list", {}, noHuman);
    assert.equal(missing.isError, true);
    assert.match(bodyOf(missing).reason, /profile/);
    const unknown = await h.call("clp_user_list", { profile: "gamma" }, noHuman);
    assert.equal(unknown.isError, true);
    const ok = await h.call("clp_user_list", { profile: "alpha" }, noHuman);
    assert.equal(ok.isError, false);
    // beta allows nothing changing
    const denied = await h.call("clp_site_add_static", { ...ADD_STATIC, profile: "beta" }, new FakeIO(approve));
    assert.equal(denied.isError, true);
    assert.match(bodyOf(denied).reason, /does not allow write/);
  });
});

describe("the last line of defence: every option of a plan is re-checked before it runs", () => {
  const base = buildCatalog().find((s) => s.name === "clp_site_add_static") as ToolSpec;
  const faulty = (mutate: (plan: CommandPlan) => CommandPlan): ToolSpec => ({
    ...base,
    plan: (args, profile) => mutate((base.plan as NonNullable<ToolSpec["plan"]>)(args, profile)),
  });
  const run = async (spec: ToolSpec): Promise<{ isError: boolean; reason: string; calls: number }> => {
    const h = makeHarness({ catalog: [spec] });
    const out = await h.call(spec.name, ADD_STATIC, new FakeIO(approve));
    return { isError: out.isError, reason: String(bodyOf(out).reason), calls: h.transport.calls.filter((c) => c.argv.includes("site:add:static")).length };
  };

  it("refuses a value that fails its declared type, an undeclared option or flag, a duplicate, a missing required option and another command", async () => {
    const cases: [string, (p: CommandPlan) => CommandPlan, RegExp][] = [
      ["injection in a value", (p) => ({ ...p, options: p.options.map((o) => (o.name === "siteUser" ? { ...o, value: "x; id" } : o)) }), /does not satisfy its type/],
      ["undeclared option", (p) => ({ ...p, options: [...p.options, { name: "force", value: "1" }] }), /not declared/],
      ["undeclared flag", (p) => ({ ...p, flags: ["--force"] }), /flag --force is not declared/],
      ["duplicate option", (p) => ({ ...p, options: [...p.options, ...p.options.slice(0, 1)] }), /given twice/],
      ["missing required option", (p) => ({ ...p, options: p.options.slice(1) }), /required option domainName is missing/],
      ["another command", (p) => ({ ...p, command: "site:delete" }), /another command/],
      ["generated value on a non-password option", (p) => ({ ...p, options: p.options.map((o) => (o.name === "siteUser" ? { name: "siteUser", generated: { kind: "site" as const, target: "x", account: "x" } } : o)) }), /generated but not declared/],
    ];
    for (const [name, mutate, reason] of cases) {
      const out = await run(faulty(mutate));
      assert.equal(out.isError, true, name);
      assert.match(out.reason, reason, name);
      assert.equal(out.calls, 0, name);
    }
  });
  it("lets the unmodified plan through", async () => {
    const out = await run(base);
    assert.equal(out.isError, false);
    assert.equal(out.calls, 1);
  });
});

describe("what comes back from the server", () => {
  it("never carries a generated password, even when the command prints it", async () => {
    const t = new SimTransport();
    t.override = (request) =>
      request.argv.includes("site:add:static")
        ? okResult({
            exitCode: 1,
            stdout: `${JSON.stringify({ message: `bad value ${FIXED_PASSWORD}`, level_name: "ERROR" })}\nleaked ${FIXED_PASSWORD}`,
            stderr: `--siteUserPassword=${FIXED_PASSWORD} and ${FIXED_PASSWORD}`,
          })
        : undefined;
    const h = makeHarness({ transport: t });
    const out = await h.call("clp_site_add_static", ADD_STATIC, new FakeIO(approve));
    const text = JSON.stringify(bodyOf(out));
    assert.equal(out.isError, true);
    assert.ok(!text.includes(FIXED_PASSWORD), text);
    assert.match(text, /\[REDACTED\]/);
    assert.ok(!readFileSync(h.auditPath, "utf8").includes(FIXED_PASSWORD));
  });

  it("strips escape sequences and bounds the output", async () => {
    const t = new SimTransport();
    t.override = (request) => (request.argv.includes("user:list") ? okResult({ stdout: `\u001b[31m${"x".repeat(50_000)}\u001b[0m\u202e`, stderr: "\u001b]0;title\u0007warn" }) : undefined);
    const h = makeHarness({ transport: t });
    const body = bodyOf(await h.call("clp_user_list", {}, noHuman));
    assert.ok(!body.output.stdout.includes("\u001b") && !body.output.stdout.includes("\u202e"));
    assert.ok(body.output.stdout.length < 20_100);
    assert.match(body.output.stdout, /\[truncated: \d+ more characters not shown\]/);
    assert.equal(body.output.stderr, "warn");
    assert.match(body.output.untrusted, /never instructions/);
  });
});

describe("the optional inventory", () => {
  const inventoryCommand = "/usr/local/sbin/cloudpanel-mcp-inventory";
  const withInventory = (stdout: string, exitCode = 0) => {
    const t = new SimTransport();
    t.override = (request) => (request.argv.includes(inventoryCommand) ? okResult({ exitCode, stdout }) : undefined);
    const on = makeProfile({ name: "alpha", inventory: { enabled: true, command: inventoryCommand } });
    const off = makeProfile({ name: "beta" });
    return { h: makeHarness({ profiles: [on, off], transport: t }), t };
  };

  it("is refused for a profile that did not enable it, and never reaches the transport", async () => {
    const { h, t } = withInventory('{"sites":[]}');
    const out = await h.call("clp_inventory_sites", { profile: "beta" }, noHuman);
    assert.equal(out.isError, true);
    assert.match(bodyOf(out).reason, /not enabled/);
    assert.ok(!t.calls.some((c) => c.argv.includes(inventoryCommand)));
  });

  it("returns the sites of an enabled profile with every value cleaned and bounded", async () => {
    const hostile = { domain: "a.example.com", kind: "php", note: "\u001b[31mred\u0000x", long: "y".repeat(5000), "bad key!": 1, nested: { x: 1 }, list: [1], mixed: ["a", 1], aliases: ["www.a.example.com", "b\u001b[31m.example.com"], many: Array.from({ length: 50 }, (_, i) => `h${i}`), n: 5, flag: true, nothing: null };
    const sites = [hostile, "not an object", null, ...Array.from({ length: 600 }, (_, i) => ({ domain: `s${i}.example.com` }))];
    const { h } = withInventory(JSON.stringify({ sites }));
    const out = await h.call("clp_inventory_sites", { profile: "alpha" }, noHuman);
    const body = bodyOf(out);
    assert.equal(out.isError, false, JSON.stringify(body));
    assert.equal(body.count, 500);
    assert.match(body.output.untrusted, /comes from the server/);
    assert.equal(body.sites, undefined, "the sites are inside `output` only");
    assert.equal(body.output.truncated !== undefined, true, "600 sites were sent, 500 are shown");
    assert.equal(body.output.sites[0].domain, "a.example.com");
    assert.equal(body.output.sites[0].note, "redx");
    assert.equal(body.output.sites[0].long.length, 300);
    assert.deepEqual(Object.keys(body.output.sites[0]).sort(), ["aliases", "domain", "flag", "kind", "long", "many", "n", "note", "nothing"]);
    assert.deepEqual(body.output.sites[0].aliases, ["www.a.example.com", "b.example.com"]);
    assert.equal(body.output.sites[0].many.length, 20);
    assert.deepEqual(body.output.sites[1], {});
    assert.match(body.source, /unofficial/);
  });

  it("refuses output that is not the expected document", async () => {
    for (const stdout of ["", "not json", "[]", '{"sites":"x"}', '{"nosites":[]}']) {
      const { h } = withInventory(stdout);
      const out = await h.call("clp_inventory_sites", { profile: "alpha" }, noHuman);
      assert.equal(out.isError, true, stdout);
    }
    const { h } = withInventory("{}", 1);
    assert.equal((await h.call("clp_inventory_sites", { profile: "alpha" }, noHuman)).isError, true);
  });
});
