import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { buildCatalog } from "../src/catalog/index.ts";
import { DEFAULT_RATE_LIMITS } from "../src/config/load.ts";
import { NeedInput, type ClientIO, type Outcome } from "../src/engine.ts";
import type { ApprovalRequest, HumanDecision } from "../src/policy/approval.ts";
import { FIXED_PASSWORD, FakeIO, IS_WINDOWS, SimTransport, approve, bodyOf, makeHarness, makeProfile, noHuman, okResult } from "./helpers.ts";

const MASTER = "SIM-MASTER-PASSWORD-0123456789";
const HIDDEN = "[not shown: the output holds secrets]";
const everything = (out: Outcome): string => JSON.stringify(out.body);
const tick: HumanDecision = { action: "accept", content: { approve: true } };
const add = (name: string): Record<string, unknown> => ({ domainName: `${name}.example.com`, siteUser: `u${name}` });

describe("output that holds secrets (review finding: master credentials)", () => {
  const harness = (): ReturnType<typeof makeHarness> => makeHarness({ profile: { allow: new Set(["admin"]) } });

  it("is saved to a file and neither shown nor logged", async () => {
    const h = harness();
    const out = await h.apply("clp_db_show_master_credentials", {}, new FakeIO(approve));
    assert.equal(out.isError, false, everything(out));
    assert.equal(bodyOf(out).output.stdout, HIDDEN);
    assert.equal(bodyOf(out).output.stderr, HIDDEN);
    assert.equal(typeof bodyOf(out).secretsFile, "string");
    assert.ok(!everything(out).includes(MASTER));
    assert.ok(!JSON.stringify(h.audit()).includes(MASTER));
  });

  it("is still not shown when saving it fails", { skip: IS_WINDOWS }, async () => {
    const h = harness();
    writeFileSync(join(h.stateDir, "secrets"), "a file where the secrets directory should be");
    const out = await h.apply("clp_db_show_master_credentials", {}, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).output.stdout, HIDDEN);
    assert.equal(bodyOf(out).output.stderr, HIDDEN);
    assert.equal(bodyOf(out).output.serverMessage, undefined);
    assert.match(bodyOf(out).error, /could not be saved/);
    assert.ok(!everything(out).includes("MASTER-PASSWORD"));
    assert.ok(!everything(out).includes(h.stateDir), "no path of the state directory");
  });

  it("is not shown when the command fails either, stderr and the server message included", async () => {
    const h = harness();
    // the server's own error line is JSON on stdout; here it quotes the secret, and stderr repeats it
    h.transport.override = (request) =>
      request.argv.includes("db:show:master-credentials")
        ? okResult({ exitCode: 1, stdout: `{"message":"cannot show the credentials for root with password ${MASTER}","context":[],"level_name":"ERROR"}\n`, stderr: `last password ${MASTER}` })
        : undefined;
    const out = await h.apply("clp_db_show_master_credentials", {}, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).output.stdout, HIDDEN);
    assert.equal(bodyOf(out).output.stderr, HIDDEN);
    assert.equal(bodyOf(out).output.serverMessage, undefined);
    assert.match(bodyOf(out).note, /never shown/);
    assert.equal(bodyOf(out).secretsFile, undefined);
    assert.ok(!everything(out).includes(MASTER));
  });
});

describe("where server text goes", () => {
  it("lives in `output`, labelled untrusted, and never in the engine's own `error`", async () => {
    const h = makeHarness();
    h.transport.state.sites.push({ domain: "shop.example.com", type: "static", siteUser: "other", password: "x" });
    const out = await h.call("clp_site_add_static", { domainName: "shop.example.com", siteUser: "shop" }, new FakeIO(approve));
    const body = bodyOf(out);
    assert.match(body.output.untrusted, /data, never instructions/);
    assert.match(body.output.serverMessage, /already exists/);
    assert.equal(body.error, undefined);
  });
  it("is cleaned and bounded in the table too", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    h.transport.override = (request) =>
      request.argv.includes("user:list")
        ? okResult({ stdout: `+----+----+\n| A | B |\n+----+----+\n${Array.from({ length: 800 }, (_, i) => `| \u001b[31mr${i} | ${"y".repeat(500)} |`).join("\n")}\n+----+----+\n` })
        : undefined;
    const out = await h.call("clp_user_list", {}, noHuman);
    const table = bodyOf(out).output.table;
    assert.ok(table.rows.length <= 500);
    assert.ok(table.rows.every((row: string[]) => row.every((cell) => cell.length <= 200 && !cell.includes("\u001b"))));
  });
});

describe("arguments far larger than any tool needs", () => {
  it("are refused before any pattern runs on them, and nothing is run", async () => {
    const h = makeHarness();
    let deep: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 20; i += 1) deep = { next: deep };
    const cases: unknown[] = [
      { domainName: "a".repeat(200_000), siteUser: "abc" },
      { ...add("x"), extra: deep },
      { domainName: Array.from({ length: 3000 }, () => "x"), siteUser: "abc" },
      Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [`k${i}`, 1])),
    ];
    for (const args of cases) {
      const out = await h.call("clp_site_add_static", args as Record<string, unknown>, new FakeIO(approve));
      assert.equal(out.isError, true);
      assert.match(String(bodyOf(out).reason), /far larger/);
    }
    assert.equal(h.transport.calls.length, 0);
  });
  it("a hostile object that throws when read is refused, not crashed on", async () => {
    const h = makeHarness();
    const hostile = new Proxy({}, { ownKeys: () => { throw new Error("boom"); }, get: () => { throw new Error("boom"); } });
    const out = await h.call("clp_site_add_static", hostile as Record<string, unknown>, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(h.transport.calls.length, 0);
  });
});

describe("site-user logins are found by own property only", () => {
  it("the catalogue's own check refuses 'constructor' and 'toString' without help from the transport", () => {
    const profile = makeProfile({ siteUserAccess: { shop: { host: "shop-alias" } } });
    for (const name of ["clp_system_permissions_reset", "clp_varnish_cache_purge"]) {
      const spec = buildCatalog().find((s) => s.name === name);
      assert.ok(spec?.check !== undefined);
      assert.equal(spec.check({ siteUser: "shop", purge: "all" }, profile), null);
      for (const user of ["constructor", "toString", "__proto__", "hasOwnProperty", "other"]) {
        assert.match(String(spec.check({ siteUser: user, purge: "all" }, profile)), /no SSH login/, user);
      }
    }
  });
  it("'constructor' is not a configured site user", async () => {
    const h = makeHarness({ profile: { siteUserAccess: { shop: { host: "shop-alias" } } } });
    const out = await h.call("clp_system_permissions_reset", { siteUser: "constructor" }, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(String(bodyOf(out).reason), /no SSH login/);
    assert.equal(h.transport.calls.length, 0);
  });
});

describe("approval questions", () => {
  it("are put one at a time per profile", async () => {
    const h = makeHarness();
    let release: (decision: HumanDecision) => void = () => undefined;
    const slow: ClientIO = {
      canElicitForm: true,
      ask: () => new Promise<HumanDecision>((resolve) => { release = resolve; }),
    };
    const first = h.call("clp_site_add_static", add("aa"), slow);
    await new Promise((resolve) => setImmediate(resolve));
    const second = await h.call("clp_site_add_static", add("bb"), new FakeIO(approve));
    assert.equal(second.isError, true);
    assert.match(String(bodyOf(second).reason), /already waiting/);
    release(tick);
    assert.equal((await first).isError, false);
    assert.equal((await h.call("clp_site_add_static", add("bb"), new FakeIO(approve))).isError, false);
  });

  it("are limited per profile whether the human says yes or no", async () => {
    const h = makeHarness({ profile: { rateLimits: { ...DEFAULT_RATE_LIMITS, ask: { max: 2, perMinutes: 10 } } } });
    const no = new FakeIO({ action: "decline" });
    for (const name of ["aa", "bb"]) {
      const out = await h.call("clp_site_add_static", add(name), no);
      assert.equal(out.isError, true);
      assert.equal(bodyOf(out).decision, "decline");
    }
    const third = await h.call("clp_site_add_static", add("cc"), no);
    assert.match(String(bodyOf(third).reason), /too many approval questions/);
    assert.equal(no.asked.length, 2);
  });

  it("count once in the 2026 era, where the call is re-run with the answer", async () => {
    const h = makeHarness({ profile: { rateLimits: { ...DEFAULT_RATE_LIMITS, ask: { max: 2, perMinutes: 10 } } } });
    const cycle = async (name: string): Promise<Outcome> => {
      await assert.rejects(h.call("clp_site_add_static", add(name), new FakeIO(undefined, { replaysAnswers: true })), NeedInput);
      return h.call("clp_site_add_static", add(name), new FakeIO(tick, { replaysAnswers: true }));
    };
    assert.equal((await cycle("aa")).isError, false);
    assert.equal((await cycle("bb")).isError, false);
    const blocked = await h.call("clp_site_add_static", add("cc"), new FakeIO(undefined, { replaysAnswers: true }));
    assert.equal(blocked.isError, true);
    assert.match(String(bodyOf(blocked).reason), /too many approval questions/);
  });

  it("carry a key that belongs to the plan token, so an answer for one plan cannot be replayed for another", async () => {
    const h = makeHarness();
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    const token = async (): Promise<string> => {
      const plan = await h.call("clp_site_delete", { domainName: "old.example.com", dryRun: true }, new FakeIO(approve));
      return String(bodyOf(plan).planToken);
    };
    const keyFor = async (planToken: string): Promise<string> => {
      try {
        await h.call("clp_site_delete", { domainName: "old.example.com", planToken }, new FakeIO(undefined));
      } catch (error) {
        if (error instanceof NeedInput) return error.request.key;
        throw error;
      }
      throw new Error("expected a question");
    };
    const [t1, t2] = [await token(), await token()];
    const [k1, k2, k1again] = [await keyFor(t1), await keyFor(t2), await keyFor(t1)];
    assert.notEqual(k1, k2);
    assert.equal(k1, k1again);
  });
});

describe("the audit log is a precondition", () => {
  const secretFilesOf = (stateDir: string): string[] => (existsSync(join(stateDir, "secrets", "test")) ? readdirSync(join(stateDir, "secrets", "test")) : []);
  const cases: [string, Parameters<typeof makeHarness>[0], string][] = [
    ["the approval record", { failAudit: (entry) => entry.event === "approval" }, "approval"],
    ["the start record", { failAudit: (entry) => entry.event === "start" }, "start"],
    ["the approval record, when the client approves writes itself", { profile: { approvalWrite: "client" }, failAudit: (entry) => entry.event === "approval" }, "approval"],
  ];
  for (const [name, options, event] of cases) {
    it(`nothing is run when ${name} cannot be written`, async () => {
      const h = makeHarness(options);
      const out = await h.call("clp_site_add_static", add("aa"), new FakeIO(approve));
      assert.equal(out.isError, true);
      assert.match(String(bodyOf(out).reason), /nothing is run/);
      assert.equal(h.transport.state.sites.length, 0);
      assert.equal(h.transport.calls.filter((c) => c.argv.includes("site:add:static")).length, 0, `the command was not even sent (${event})`);
      assert.deepEqual(secretFilesOf(h.stateDir), [], "no password file is left behind");
    });
  }
});

describe("the audit log is a precondition (a log that cannot be written at all)", { skip: IS_WINDOWS }, () => {
  it("nothing is run when it cannot be written", async () => {
    const h = makeHarness();
    const plan = await h.call("clp_site_add_static", { ...add("aa"), dryRun: true }, new FakeIO(approve));
    assert.equal(plan.isError, false);
    rmSync(h.auditPath, { force: true });
    mkdirSync(h.auditPath); // a directory where the log file should be
    const out = await h.call("clp_site_add_static", add("aa"), new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(String(bodyOf(out).reason), /nothing is run/);
    assert.equal(h.transport.state.sites.length, 0);
  });
});

/** A client of the 2026 era: it re-sends the call with the answers it holds, keyed by the question's key. */
class KeyedIO implements ClientIO {
  readonly canElicitForm = true;
  readonly replaysAnswers = true;
  /** The questions that came back to this client (the NeedInput of each call that was not answered). */
  readonly asked: ApprovalRequest[] = [];
  readonly answers = new Map<string, HumanDecision>();

  async ask(request: ApprovalRequest): Promise<HumanDecision> {
    const held = this.answers.get(request.key);
    if (held === undefined) throw new NeedInput(request);
    return held;
  }

  answerFor(key: string): HumanDecision | undefined {
    return this.answers.get(key);
  }

  /** What the human answers to the question the server last put. */
  answer(decision: HumanDecision, key = this.asked[this.asked.length - 1]?.key): void {
    assert.ok(key !== undefined, "no question was put");
    this.answers.set(key, decision);
  }
}

const asKeyed = async (io: KeyedIO, call: () => Promise<Outcome>): Promise<ApprovalRequest> => {
  await assert.rejects(call(), (error: unknown) => {
    if (!(error instanceof NeedInput)) return false;
    io.asked.push(error.request);
    return true;
  });
  return io.asked[io.asked.length - 1] as ApprovalRequest;
};

describe("approval questions in the 2026 era: one open question, an answer used once", () => {
  const W = (name: string): [string, Record<string, unknown>] => ["clp_site_add_static", add(name)];

  it("puts a second, different question only after the first was answered", async () => {
    const h = makeHarness();
    const io = new KeyedIO();
    const first = await asKeyed(io, () => h.call(...W("aa"), io));
    // another call while the first question is open: refused, no question put
    const other = await h.call(...W("bb"), io);
    assert.equal(other.isError, true);
    assert.match(String(bodyOf(other).reason), /already waiting/);
    assert.equal(io.asked.length, 1, "the human was not asked a second question");
    // the same call again: the same question, not a new one
    const again = await asKeyed(io, () => h.call(...W("aa"), io));
    assert.equal(again.key, first.key);
    // the human answers; the replay runs the command and closes the question
    io.answer(tick);
    const done = await h.call(...W("aa"), io);
    assert.equal(done.isError, false, JSON.stringify(bodyOf(done)));
    assert.equal(h.transport.state.sites.length, 1);
    // now another question may be put
    const next = await asKeyed(io, () => h.call(...W("bb"), io));
    assert.notEqual(next.key, first.key);
  });

  it("makes an answer good for one use: a cached answer cannot approve a later identical call", async () => {
    const h = makeHarness();
    const io = new KeyedIO();
    const first = await asKeyed(io, () => h.call(...W("aa"), io));
    io.answer(tick);
    assert.equal((await h.call(...W("aa"), io)).isError, false);
    h.transport.state.sites.length = 0; // the site is gone again, and the same call is made again
    const second = await asKeyed(io, () => h.call(...W("aa"), io)); // the client still holds the old answer under the old key
    assert.notEqual(second.key, first.key, "a new question has a new key");
    assert.equal(h.transport.state.sites.length, 0, "the old answer approved nothing");
    io.answer(tick, second.key);
    assert.equal((await h.call(...W("aa"), io)).isError, false);
    assert.equal(h.transport.state.sites.length, 1);
  });

  it("an answer for another question is not an answer: the key carries the question's own nonce", async () => {
    const h = makeHarness();
    const io = new KeyedIO();
    const a = await asKeyed(io, () => h.call(...W("aa"), io));
    const other = new KeyedIO();
    other.answers.set(a.key.replace(/-[0-9a-f]+$/, "-" + "0".repeat(24)), tick); // right question, wrong nonce
    other.answers.set(a.key.replace(/-[0-9a-f]+$/, ""), tick); // right question, no nonce
    await assert.rejects(h.call(...W("aa"), other), NeedInput);
    assert.equal(h.transport.state.sites.length, 0);
  });

  it("a declined answer closes the question too", async () => {
    const h = makeHarness();
    const io = new KeyedIO();
    await asKeyed(io, () => h.call(...W("aa"), io));
    io.answer({ action: "decline" });
    const refused = await h.call(...W("aa"), io);
    assert.equal(refused.isError, true);
    assert.equal(bodyOf(refused).decision, "decline");
    await asKeyed(io, () => h.call(...W("bb"), io)); // a new question may be put
  });

  it("lets an unanswered question lapse after ten minutes", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const h = makeHarness({ now: () => now });
    const io = new KeyedIO();
    await asKeyed(io, () => h.call(...W("aa"), io));
    now += 9 * 60_000;
    assert.match(String(bodyOf(await h.call(...W("bb"), io)).reason), /already waiting/);
    now += 2 * 60_000;
    await asKeyed(io, () => h.call(...W("bb"), io));
  });

  it("charges every time the human is shown the question, but audits only a new question as asked", async () => {
    const h = makeHarness({ profile: { rateLimits: { ...DEFAULT_RATE_LIMITS, ask: { max: 3, perMinutes: 10 } } } });
    const io = new KeyedIO();
    for (let i = 0; i < 3; i += 1) await asKeyed(io, () => h.call(...W("aa"), io)); // the question and two repeats
    const asked = h.audit().filter((e) => e["event"] === "approval" && e["decision"] === "asked");
    assert.equal(asked.length, 1, "one record for the question, not one per repeat");
    const fourth = await h.call(...W("aa"), io); // a looping model cannot keep putting the form in front of the human
    assert.equal(fourth.isError, true);
    assert.match(String(bodyOf(fourth).reason), /too many approval questions/);
    assert.equal(io.asked.length, 3);
  });

  it("charges a question once when the human answers it: the re-sent call with the answer is free", async () => {
    const h = makeHarness({ profile: { rateLimits: { ...DEFAULT_RATE_LIMITS, ask: { max: 2, perMinutes: 10 } } } });
    const io = new KeyedIO();
    await asKeyed(io, () => h.call(...W("aa"), io));
    io.answer(tick);
    assert.equal((await h.call(...W("aa"), io)).isError, false);
    await asKeyed(io, () => h.call(...W("bb"), io)); // the second of two
    io.answer(tick);
    assert.equal((await h.call(...W("bb"), io)).isError, false);
    const third = await h.call(...W("cc"), io); // over the limit of two
    assert.equal(third.isError, true);
    assert.match(String(bodyOf(third).reason), /too many approval questions/);
  });

  it("lets only one of two re-sent calls use the human's answer", async () => {
    const h = makeHarness();
    const io = new KeyedIO();
    await asKeyed(io, () => h.call(...W("aa"), io));
    io.answer(tick);
    // the model sent the same call twice and the client replays both at once, each carrying the answer
    const [one, two] = await Promise.allSettled([h.call(...W("aa"), io), h.call(...W("aa"), io)]);
    const results = [one, two].map((r) => (r.status === "fulfilled" ? (r.value.isError ? "refused" : "ran") : r.reason instanceof NeedInput ? "asked again" : "threw"));
    assert.deepEqual(results.sort(), ["asked again", "ran"], JSON.stringify(results));
    assert.equal(h.transport.state.sites.length, 1, "the site was added once");
    assert.equal(h.audit().filter((e) => e["event"] === "start").length, 1);
  });

  it("lets only one of many parallel calls open a question", async () => {
    const h = makeHarness();
    const io = new KeyedIO();
    const settled = await Promise.allSettled(Array.from({ length: 8 }, (_, i) => h.call(...W(`p${i}`), io)));
    const asked = settled.filter((r) => r.status === "rejected" && r.reason instanceof NeedInput).length;
    const refused = settled.filter((r) => r.status === "fulfilled" && r.value.isError && /already waiting/.test(String(bodyOf(r.value).reason))).length;
    assert.equal(asked, 1, "one question was put to the human");
    assert.equal(refused, 7);
    assert.equal(h.audit().filter((e) => e["event"] === "approval" && e["decision"] === "asked").length, 1);
  });

  it("an open question does not outlive the plan token it was asked with", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const h = makeHarness({ now: () => now });
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    h.transport.state.sites.push({ domain: "other.example.com", type: "static", siteUser: "other", password: "x" });
    const io = new KeyedIO();
    const planned = await h.call("clp_site_delete", { domainName: "old.example.com", dryRun: true }, io);
    now += 9 * 60_000 + 30_000; // the token has thirty seconds left when the question is put
    await asKeyed(io, () => h.call("clp_site_delete", { domainName: "old.example.com", planToken: String(bodyOf(planned).planToken) }, io));
    now += 90_000; // the human answers after the token lapsed: the re-send is refused, and the question has lapsed with the token
    const late = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: String(bodyOf(planned).planToken) }, io);
    assert.equal(late.isError, true);
    assert.match(String(bodyOf(late).reason), /expired/);
    const next = await h.call("clp_site_delete", { domainName: "other.example.com", dryRun: true }, io);
    await asKeyed(io, () => h.call("clp_site_delete", { domainName: "other.example.com", planToken: String(bodyOf(next).planToken) }, io)); // not "already waiting"
  });

  it("keeps the questions of two profiles apart", async () => {
    const a = makeProfile({ name: "alpha" });
    const b = makeProfile({ name: "beta" });
    const h = makeHarness({ profiles: [a, b] });
    const io = new KeyedIO();
    await asKeyed(io, () => h.call("clp_site_add_static", { ...add("aa"), profile: "alpha" }, io));
    await asKeyed(io, () => h.call("clp_site_add_static", { ...add("aa"), profile: "beta" }, io));
    const blocked = await h.call("clp_site_add_static", { ...add("bb"), profile: "alpha" }, io);
    assert.match(String(bodyOf(blocked).reason), /already waiting/);
  });
});

describe("a plan token is checked again after the human has decided", () => {
  it("a token that lapsed while the human thought about it is refused", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const h = makeHarness({ now: () => now });
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    const plan = await h.call("clp_site_delete", { domainName: "old.example.com", dryRun: true }, new FakeIO(approve));
    const slow = new FakeIO((request) => {
      now += 11 * 60_000; // the human takes eleven minutes: the token was good for ten
      return request.kind === "type-target" ? { action: "accept", content: { typed: request.target } } : tick;
    });
    const out = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: String(bodyOf(plan).planToken) }, slow);
    assert.equal(out.isError, true);
    assert.match(String(bodyOf(out).reason), /expired/);
    assert.equal(h.transport.state.sites.length, 1, "nothing was deleted");
  });
});

describe("what the server does for reads", () => {
  it("writes an audit record for a read, too", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    assert.equal((await h.call("clp_user_list", {}, noHuman)).isError, false);
    const ends = h.audit().filter((e) => e["event"] === "end" && e["tool"] === "clp_user_list");
    assert.equal(ends.length, 1);
    assert.equal(ends[0]?.["class"], "read");
    assert.equal(ends[0]?.["ok"], true);
  });

  it("runs at most four reads at a time on one profile", async () => {
    class CountingTransport extends SimTransport {
      active = 0;
      most = 0;
      override async run(request: Parameters<SimTransport["run"]>[0]): ReturnType<SimTransport["run"]> {
        this.active += 1;
        this.most = Math.max(this.most, this.active);
        await new Promise((resolve) => setTimeout(resolve, 15));
        try {
          return await super.run(request);
        } finally {
          this.active -= 1;
        }
      }
    }
    const transport = new CountingTransport();
    const h = makeHarness({ profile: { allow: new Set() }, transport });
    const outcomes = await Promise.all(Array.from({ length: 12 }, () => h.call("clp_user_list", {}, noHuman)));
    assert.ok(outcomes.every((o) => !o.isError));
    assert.ok(transport.most <= 4, `${transport.most} at once`);
    assert.ok(transport.most >= 2, "but they did run side by side");
  });

  it("answers a forced re-detection from the cache within thirty seconds", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const h = makeHarness({ profile: { allow: new Set() }, now: () => now });
    const probes = (): number => h.transport.calls.filter((c) => c.argv.length <= 3 && !c.argv.includes("user:list")).length;
    await h.call("clp_list_commands", {}, noHuman);
    const first = probes();
    assert.ok(first >= 1);
    for (let i = 0; i < 5; i += 1) await h.call("clp_list_commands", { refresh: true }, noHuman);
    assert.equal(probes(), first, "five forced re-detections cost no probe");
    now += 31_000;
    await h.call("clp_list_commands", { refresh: true }, noHuman);
    assert.equal(probes(), first + 1, "after thirty seconds one is allowed");
  });
});

describe("tables from the server", () => {
  it("a generated password in a table cell is not shown", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    h.redactor.add(FIXED_PASSWORD);
    h.transport.override = (request) =>
      request.argv.includes("user:list")
        ? okResult({ stdout: `+------+------+\n| User | Note |\n+------+------+\n| a    | ${FIXED_PASSWORD} |\n+------+------+\n` })
        : undefined;
    const out = await h.call("clp_user_list", {}, noHuman);
    const body = bodyOf(out);
    assert.equal(body.output.table.rows[0][1], "[REDACTED]");
    assert.ok(!JSON.stringify(body).includes(FIXED_PASSWORD));
  });
});

describe("detection under concurrency", () => {
  it("fifty parallel forced re-detections cost one probe", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const h = makeHarness({ profile: { allow: new Set() }, now: () => now });
    const probes = (): number => h.transport.calls.filter((c) => c.argv.length === 1).length;
    await h.call("clp_list_commands", {}, noHuman);
    const before = probes();
    now += 31_000;
    const outcomes = await Promise.all(Array.from({ length: 50 }, () => h.call("clp_list_commands", { refresh: true }, noHuman)));
    assert.ok(outcomes.every((o) => !o.isError));
    assert.equal(probes() - before, 1);
  });
});

describe("text decoded after the scrubbing is scrubbed again", () => {
  it("a server message whose JSON escapes spell a generated password does not show it", async () => {
    const h = makeHarness();
    // the password is written with JSON escapes, which only JSON decoding turns into the password
    const escaped = FIXED_PASSWORD.split("").map((c) => `\\u00${c.charCodeAt(0).toString(16)}`).join("");
    h.transport.override = (request) =>
      request.argv.includes("site:add:static")
        ? okResult({ exitCode: 1, stdout: `{"message":"cannot add the site; the password ${escaped} was refused and --password=hunter2xyz too","context":[],"level_name":"ERROR"}\n` })
        : undefined;
    const out = await h.call("clp_site_add_static", add("aa"), new FakeIO(approve));
    assert.equal(out.isError, true);
    const shown = String(bodyOf(out).output.serverMessage);
    assert.match(shown, /cannot add the site/);
    assert.ok(!shown.includes(FIXED_PASSWORD), shown);
    assert.ok(!shown.includes("hunter2xyz"), shown);
    assert.ok(!JSON.stringify(out.body).includes(FIXED_PASSWORD));
  });

  it("an inventory value is scrubbed whole before it is cut, so a cut cannot bring part of a password into view", async () => {
    const inventoryCommand = "/usr/local/sbin/cloudpanel-mcp-inventory";
    const transport = new SimTransport();
    const h0 = makeHarness();
    // register the generated password with the redactor, as a command that generated one would
    h0.redactor.add(FIXED_PASSWORD);
    const secret = FIXED_PASSWORD;
    // 14 copies shrink the text by 14 * 22 = 308 characters once they are replaced; a whole copy that starts at 590 would be cut in two
    // at 600 if the text were cut first, and its first ten characters would then sit inside the 300 that are kept
    const note = `${secret.repeat(14)}${"x".repeat(590 - 14 * 32)}${secret}`;
    transport.override = (request) => (request.argv.includes(inventoryCommand) ? okResult({ stdout: JSON.stringify({ sites: [{ domain: "a.example.com", note }] }) }) : undefined);
    const profile = makeProfile({ name: "alpha", inventory: { enabled: true, command: inventoryCommand } });
    const h = makeHarness({ profiles: [profile], transport });
    h.redactor.add(secret);
    const body = bodyOf(await h.call("clp_inventory_sites", {}, noHuman));
    const shown = String(body.output.sites[0].note);
    assert.ok(shown.length <= 300);
    assert.ok(!shown.includes(secret.slice(0, 8)), shown);
    assert.ok(shown.endsWith("[REDACTED]"), shown.slice(-40));
  });
});

describe("what a model can make the audit log grow by", () => {
  it("writes the name of an unknown tool as short printable text", async () => {
    const h = makeHarness();
    await h.call(`clp_${String.fromCodePoint(0x202e)}${String.fromCodePoint(7)}é日本` + "x".repeat(500), {}, noHuman);
    const refused = h.audit().filter((e) => e["event"] === "refused");
    assert.equal(refused.length, 1);
    const tool = String(refused[0]?.["tool"]);
    assert.ok(tool.length <= 80, String(tool.length));
    assert.match(tool, /^[\x20-\x7e]*$/);
  });
});

describe("what the server lists is bounded and sits in `output`", () => {
  it("clp_list_commands shows at most 300 command names, says how many it left out, and only inside `output`", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    h.transport.override = (request) =>
      request.argv.length === 1
        ? okResult({ stdout: Array.from({ length: 700 }, (_, i) => `clpctl cmd${i}:run`).join("\n") + "\n" })
        : undefined;
    const body = bodyOf(await h.call("clp_list_commands", {}, noHuman));
    assert.equal(body.output.commandsOnServer.length, 300);
    assert.equal(body.output.notShown.commands, 400);
    assert.equal(body.output.commandsOnServerWithoutATool.length, 100);
    assert.ok(body.output.notShown.withoutATool >= 500);
    assert.equal(body.commandsOnServer, undefined);
    assert.equal(body.commandsOnServerWithoutATool, undefined);
    assert.ok(JSON.stringify(body).length < 40_000, String(JSON.stringify(body).length));
  });

  it("clp_inventory_sites stops adding sites when the document would exceed 60,000 characters", async () => {
    const inventoryCommand = "/usr/local/sbin/cloudpanel-mcp-inventory";
    const transport = new SimTransport();
    const long = "y".repeat(300);
    const sites = Array.from({ length: 400 }, (_, i) => ({ domain: `s${i}.example.com`, a: long, b: long, c: long, d: long, e: long }));
    transport.override = (request) => (request.argv.includes(inventoryCommand) ? okResult({ stdout: JSON.stringify({ sites }) }) : undefined);
    const profile = makeProfile({ name: "alpha", inventory: { enabled: true, command: inventoryCommand } });
    const h = makeHarness({ profiles: [profile], transport });
    const body = bodyOf(await h.call("clp_inventory_sites", {}, noHuman));
    assert.ok(body.count > 10 && body.count < 400, String(body.count));
    assert.equal(body.output.sites.length, body.count);
    assert.match(body.output.truncated, /more sites exist/);
    assert.ok(JSON.stringify(body.output.sites).length <= 61_000);
  });
});

// ---------------------------------------------------------------------------------------------- review round 4

describe("a question clpctl asks and nobody can answer (review round 4)", () => {
  const withDb = (): ReturnType<typeof makeHarness> => {
    const h = makeHarness();
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    h.transport.state.dbs.push({ name: "shopdb", user: "shopu", domain: "old.example.com", password: "x" });
    return h;
  };
  const question = "Confirm to delete the database: shopdb (yes/no): ";

  it("db:delete is done when clpctl itself then says that this database has been deleted", async () => {
    const h = withDb();
    const out = await h.apply("clp_db_delete", { databaseName: "shopdb" }, new FakeIO(approve));
    assert.equal(out.isError, false, everything(out));
    assert.match(String(bodyOf(out).output.stderr), /\(yes\/no\)/, "the simulator asks, as clpctl does");
    assert.equal(bodyOf(out).unconfirmed, undefined);
    assert.equal(h.transport.state.dbs.length, 0);
  });

  it("the question alone, with exit status 0, is reported as not confirmed", async () => {
    for (const result of [
      okResult({ stderr: question }),
      okResult({ stdout: question }),
      okResult({ stderr: question, stdout: "The database otherdb has been deleted.\n" }),
    ]) {
      const h = withDb();
      h.transport.override = (request) => (request.argv.some((word) => word.includes("db:delete")) ? result : undefined);
      const out = await h.apply("clp_db_delete", { databaseName: "shopdb" }, new FakeIO(approve));
      assert.equal(out.isError, true, everything(out));
      assert.equal(bodyOf(out).ok, false);
      assert.equal(bodyOf(out).unconfirmed, true);
      assert.match(String(bodyOf(out).note), /not confirmed/);
      const end = h.audit().filter((e) => e["event"] === "end" && e["tool"] === "clp_db_delete");
      assert.equal(end.length, 1);
      assert.equal(end[0]?.["ok"], false);
    }
  });

  it("holds for every changing tool, and a generated password is then said to be probably unused", async () => {
    const h = makeHarness();
    h.transport.override = (request) => (request.argv.some((word) => word.includes("site:add:static")) ? okResult({ stdout: "Are you sure? (yes/no) " }) : undefined);
    const out = await h.call("clp_site_add_static", add("aa"), new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).unconfirmed, true);
    assert.match(String(bodyOf(out).passwordNote), /probably never applied/);
  });

  it("does not turn a read into a failure", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    h.transport.override = (request) =>
      request.argv.some((word) => word.includes("user:list")) ? okResult({ stdout: "+------+\n| Note |\n+------+\n| asks (yes/no) |\n+------+\n" }) : undefined;
    const out = await h.call("clp_user_list", {}, noHuman);
    assert.equal(out.isError, false, everything(out));
  });
});

describe("an error line that the scrubbing would cut into (review round 4)", () => {
  const line = (password: string): string => `{"message":"Command failed: site:add:static --siteUserPassword=${password}","context":[],"level_name":"ERROR"}\n`;

  it("is still seen when the exit status is 0, whether the password is one this server generated or not", async () => {
    for (const password of [FIXED_PASSWORD, "hunter2xyz-unknown"]) {
      const h = makeHarness();
      h.transport.override = (request) => (request.argv.some((word) => word.includes("site:add:static")) ? okResult({ stdout: line(password) }) : undefined);
      const out = await h.call("clp_site_add_static", add("aa"), new FakeIO(approve));
      assert.equal(out.isError, true, everything(out));
      assert.match(String(bodyOf(out).output.serverMessage), /Command failed/);
      assert.match(String(bodyOf(out).passwordNote), /probably never applied/);
      assert.ok(!everything(out).includes(password), everything(out));
      assert.ok(!JSON.stringify(h.audit()).includes(password));
    }
  });

  it("the command in the audit log is the command the human was shown, quote for quote", async () => {
    const h = makeHarness({ profile: { allow: new Set(["admin"]) } });
    const io = new FakeIO(approve);
    const out = await h.apply("clp_user_add", { userName: "jane.doe", email: "jane@example.com", firstName: "Jane", lastName: "Doe", role: "admin", timezone: "UTC", status: "1" }, io);
    assert.equal(out.isError, false, everything(out));
    const shown = String(bodyOf(out).command);
    assert.match(shown, /'--password=\[REDACTED\]' /);
    for (const entry of h.audit().filter((e) => e["event"] === "start" || e["event"] === "end")) assert.equal(entry["command"], shown);
  });
});

describe("a duplicate of a call the human has approved (review round 4)", () => {
  it("is refused as already used and leaves no question behind that nobody could answer", async () => {
    const h = makeHarness();
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    const io = new KeyedIO();
    const plan = await h.call("clp_site_delete", { domainName: "old.example.com", dryRun: true }, io);
    const args = { domainName: "old.example.com", planToken: String(bodyOf(plan).planToken) };
    await asKeyed(io, () => h.call("clp_site_delete", args, io));
    io.answer({ action: "accept", content: { typed: "old.example.com" } });
    // the client replays the call with the answer, and the model sent the same call a second time in the same turn
    const [one, two] = await Promise.allSettled([h.call("clp_site_delete", args, io), h.call("clp_site_delete", args, io)]);
    const results = [one, two].map((r) => (r.status === "fulfilled" ? (r.value.isError ? String(bodyOf(r.value).reason) : "ran") : r.reason instanceof NeedInput ? "asked again" : "threw"));
    assert.equal(results.filter((r) => r === "ran").length, 1, JSON.stringify(results));
    assert.equal(results.filter((r) => /already used/.test(r)).length, 1, JSON.stringify(results));
    assert.equal(h.transport.state.sites.length, 0);
    assert.equal(h.audit().filter((e) => e["event"] === "start").length, 1);
    assert.equal(h.audit().filter((e) => e["event"] === "approval" && e["decision"] === "asked").length, 1, "no second question was put for the approved token");
    // the profile is free at once: another changing call can put its own question
    const next = await asKeyed(io, () => h.call("clp_site_add_static", add("bb"), io));
    assert.match(next.key, /^approve-/);
  });

  it("a plan token is good once also where the profile leaves write approval to the client", async () => {
    const h = makeHarness({ profile: { approvalWrite: "client" } });
    const plan = await h.call("clp_site_add_static", { ...add("aa"), dryRun: true }, noHuman);
    const args = { ...add("aa"), planToken: String(bodyOf(plan).planToken) };
    assert.equal((await h.call("clp_site_add_static", args, noHuman)).isError, false);
    const again = await h.call("clp_site_add_static", args, noHuman);
    assert.equal(again.isError, true);
    assert.match(String(bodyOf(again).reason), /already used/);
    assert.equal(h.audit().filter((e) => e["event"] === "start").length, 1);
  });

  it("the human's decision is recorded even when the token lapsed while they were deciding", async () => {
    let now = Date.parse("2026-01-01T00:00:00Z");
    const h = makeHarness({ now: () => now });
    h.transport.state.sites.push({ domain: "old.example.com", type: "static", siteUser: "old", password: "x" });
    const plan = await h.call("clp_site_delete", { domainName: "old.example.com", dryRun: true }, new FakeIO(approve));
    const slow = new FakeIO((request) => {
      now += 11 * 60_000;
      return request.kind === "type-target" ? { action: "accept", content: { typed: request.target } } : tick;
    });
    const out = await h.call("clp_site_delete", { domainName: "old.example.com", planToken: String(bodyOf(plan).planToken) }, slow);
    assert.equal(out.isError, true);
    assert.match(String(bodyOf(out).reason), /expired/);
    const decisions = h.audit().filter((e) => e["event"] === "approval" && e["decision"] === "accept");
    assert.equal(decisions.length, 1, JSON.stringify(h.audit()));
    assert.match(String(decisions[0]?.["note"]), /nothing is run: .*expired/);
    assert.equal(h.audit().filter((e) => e["event"] === "start").length, 0);
    assert.equal(h.transport.state.sites.length, 1);
  });
});

describe("reads that run no clpctl command of their own are recorded too (review round 4)", () => {
  it("clp_server_info, clp_list_commands and clp_inventory_sites each leave one record", async () => {
    const inventoryCommand = "/usr/local/sbin/cloudpanel-mcp-inventory";
    const transport = new SimTransport();
    transport.override = (request) => (request.argv.includes(inventoryCommand) ? okResult({ stdout: JSON.stringify({ sites: [{ domain: "a.example.com" }] }) }) : undefined);
    const profile = makeProfile({ name: "alpha", inventory: { enabled: true, command: inventoryCommand } });
    const h = makeHarness({ profiles: [profile], transport });
    for (const tool of ["clp_server_info", "clp_list_commands", "clp_inventory_sites"]) {
      assert.equal((await h.call(tool, {}, noHuman)).isError, false, tool);
      const ends = h.audit().filter((e) => e["event"] === "end" && e["tool"] === tool);
      assert.equal(ends.length, 1, tool);
      assert.equal(ends[0]?.["class"], "read");
      assert.equal(ends[0]?.["ok"], true);
    }
  });
});

describe("a table whose cell looks like a password option (review round 4)", () => {
  it("keeps its columns", async () => {
    const h = makeHarness({ profile: { allow: new Set() } });
    const table = [
      "+-----------+-------------+-----------+---------------+-------+--------+",
      "| User Name | First Name  | Last Name | E-Mail        | Role  | Status |",
      "+-----------+-------------+-----------+---------------+-------+--------+",
      "| jd        | x--password | Doe       | j@example.com | admin | Active |",
      "+-----------+-------------+-----------+---------------+-------+--------+",
      "",
    ].join("\n");
    h.transport.override = (request) => (request.argv.some((word) => word.includes("user:list")) ? okResult({ stdout: table }) : undefined);
    const body = bodyOf(await h.call("clp_user_list", {}, noHuman));
    assert.deepEqual(body.output.table.rows[0], ["jd", "x--password", "Doe", "j@example.com", "admin", "Active"]);
    assert.match(String(body.output.stdout), /\| x--password \| Doe /);
  });
});
