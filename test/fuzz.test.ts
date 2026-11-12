import assert from "node:assert/strict";
import { describe, it } from "node:test";
import fc from "fast-check";
import { buildCatalog } from "../src/catalog/index.ts";
import { DEFAULT_RATE_LIMITS } from "../src/config/load.ts";
import { FIXED_PASSWORD, FakeIO, approve, makeHarness, type Harness } from "./helpers.ts";
import { HOSTILE, SAFE_TOKEN } from "./corpus.ts";
import { SAMPLE_ARGS } from "./samples.ts";

const catalog = buildCatalog();
const commandToSpec = new Map(catalog.filter((s) => s.command !== null).map((s) => [s.command as string, s]));
const HUGE = { max: 1_000_000, perMinutes: 1 };

function harness(): Harness {
  return makeHarness({
    profile: {
      siteUserAccess: { shop: { host: "shop-alias" } },
      inventory: { enabled: true, command: "/usr/local/sbin/cloudpanel-mcp-inventory" },
      rateLimits: { write: HUGE, destructive: HUGE, admin: HUGE, ask: HUGE },
    },
  });
}

/** Every command the transport was asked to run must be a catalogue command with declared, well-formed, safe tokens. */
function assertSafeRuns(h: Harness, label: string): void {
  for (const call of h.transport.calls) {
    const words = [...call.argv];
    assert.ok(words[0] !== "sudo" || (words[1] === "-n"), label);
    const program = words.shift();
    if (program === "/usr/local/sbin/cloudpanel-mcp-inventory") {
      assert.deepEqual(words, [], `${label}: the inventory script takes no arguments`);
      continue;
    }
    assert.equal(program, "/usr/bin/clpctl", label);
    if (words.length === 0) continue; // the usage-listing probe
    const command = words.shift() as string;
    const spec = commandToSpec.get(command);
    if (spec === undefined) {
      assert.fail(`${label}: ran ${JSON.stringify(call.argv)}`);
      continue;
    }
    assert.equal(call.fixedWords, call.argv.indexOf(command) + 1, `${label}: only the program and the command are left unquoted`);
    for (const token of words) {
      assert.match(token, SAFE_TOKEN, `${label}: token ${JSON.stringify(token)}`);
      const m = /^--([A-Za-z0-9]+)(?:=([\s\S]*))?$/.exec(token);
      assert.ok(m !== null, `${label}: malformed token ${JSON.stringify(token)}`);
      const [, name = "", value] = m ?? [];
      if (value === undefined) assert.ok(spec.flags.includes(`--${name}`), `${label}: undeclared flag ${token}`);
      else assert.ok(name in spec.options, `${label}: undeclared option ${name}`);
      assert.ok(!token.startsWith("---"), token);
    }
  }
}

function assertWellFormed(outcome: { isError: boolean; body: Record<string, unknown> }, label: string): void {
  assert.equal(typeof outcome.isError, "boolean", label);
  const text = JSON.stringify(outcome.body);
  assert.ok(text.length < 200_000, label);
  assert.ok(!text.includes(FIXED_PASSWORD), `${label}: the password leaked`);
  assert.equal(typeof outcome.body["ok"], "boolean", label);
  if (outcome.isError) assert.ok(outcome.body["ok"] === false, label);
}

describe("fuzzing the engine with arbitrary arguments", () => {
  it("property: whatever JSON arrives, the engine answers and runs nothing unsafe", async () => {
    const names = catalog.map((s) => s.name);
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(...names), fc.oneof(fc.anything({ maxDepth: 3 }), fc.json().map((j) => JSON.parse(j) as unknown), fc.object({ maxDepth: 2 })), async (name, args) => {
        const h = harness();
        const out = await h.call(name, args as never, new FakeIO(approve));
        assertWellFormed(out, name);
        assertSafeRuns(h, name);
        // nothing arbitrary can create or change anything: the sim state stays empty
        assert.equal(h.transport.state.sites.length + h.transport.state.dbs.length + h.transport.state.users.length, 1); // only the seeded admin
      }),
      { numRuns: 600 },
    );
  });

  it("property: random envelope fields (profile, dryRun, planToken) never get through the schema unless valid", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom("clp_site_add_static", "clp_site_delete", "clp_user_list"), fc.anything({ maxDepth: 2 }), fc.anything({ maxDepth: 2 }), fc.anything({ maxDepth: 2 }), async (name, profile, dryRun, planToken) => {
        const h = harness();
        const out = await h.call(name, { ...(SAMPLE_ARGS[name] ?? {}), profile, dryRun, planToken } as never, new FakeIO(approve));
        assertWellFormed(out, name);
        assertSafeRuns(h, name);
        // all three absent (or dryRun false) is a valid, approved call: then, and only then, the static site may exist
        const validEnvelope = profile === undefined && planToken === undefined && (dryRun === undefined || dryRun === false);
        assert.equal(h.transport.state.sites.length, validEnvelope && name === "clp_site_add_static" ? 1 : 0);
      }),
      { numRuns: 400 },
    );
  });
});

describe("hostile values in every parameter of every tool", () => {
  const weirdNumbers: unknown[] = [-1, 0, 1, 22, 1023, 3306, 8443, 65536, 1.5, 2 ** 53, "3000", null, true, [], {}, [3000], { a: 1 }];

  for (const spec of catalog) {
    it(`${spec.name}: a hostile value is refused, or it reaches clpctl as one safe token`, async () => {
      const sample = SAMPLE_ARGS[spec.name] ?? {};
      for (const [key, value] of Object.entries(sample)) {
        const candidates: readonly unknown[] =
          typeof value === "string" ? HOSTILE : typeof value === "number" ? weirdNumbers : Array.isArray(value) ? HOSTILE.map((h) => [h]) : [];
        for (const hostile of candidates) {
          const h = harness();
          const args = { ...sample, [key]: hostile };
          const io = new FakeIO(approve);
          const out = spec.cls === "read" || spec.kind === "meta" ? await h.call(spec.name, args, io) : await h.apply(spec.name, args, io);
          const label = `${spec.name}.${key}=${JSON.stringify(hostile)}`;
          assertWellFormed(out, label);
          assertSafeRuns(h, label);
        }
      }
    });

    it(`${spec.name}: an extra or renamed parameter is refused`, async () => {
      const h = harness();
      for (const extra of ["confirm", "force", "command", "shell", "args", "sudo", "password", "__proto__", "constructor", "../x"]) {
        const out = await h.call(spec.name, { ...(SAMPLE_ARGS[spec.name] ?? {}), [extra]: "x" } as never, new FakeIO(approve));
        assert.equal(out.isError, true, extra);
      }
      assertSafeRuns(h, spec.name);
    });
  }

  it("inherits nothing from Object.prototype or a polluted argument object", async () => {
    const h = harness();
    const args = JSON.parse('{"domainName":"a.example.com","siteUser":"abc","__proto__":{"force":true,"password":"x"},"constructor":{"prototype":{"polluted":1}}}');
    const out = await h.call("clp_site_add_static", args, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
    assertSafeRuns(h, "proto");
  });
});

describe("rate limits are real", () => {
  it("DEFAULT_RATE_LIMITS never allows unlimited destructive or admin calls", () => {
    assert.ok(DEFAULT_RATE_LIMITS.destructive.max <= 10 && DEFAULT_RATE_LIMITS.admin.max <= 20);
  });
});
