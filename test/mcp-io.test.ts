import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { NeedInput } from "../src/engine.ts";
import { HUMAN_TIMEOUT_MS, makeClientIO } from "../src/mcp/server.ts";
import type { ApprovalRequest } from "../src/policy/approval.ts";

const REQUEST: ApprovalRequest = {
  key: "approve-0123456789abcdef",
  kind: "type-target",
  target: "old.example.com",
  message: "Delete?",
  requestedSchema: { type: "object", properties: { typed: { type: "string" } }, required: ["typed"] },
};

type Elicit = (params: { mode: "form"; message: string; requestedSchema: never }, options?: { timeout?: number; signal?: AbortSignal }) => Promise<{ action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> }>;

function ctx(over: { envelope?: Record<string, unknown>; inputResponses?: Record<string, unknown>; elicitInput?: Elicit } = {}) {
  const controller = new AbortController();
  return {
    mcpReq: {
      signal: controller.signal,
      envelope: over.envelope,
      inputResponses: over.inputResponses,
      elicitInput: over.elicitInput ?? (async () => ({ action: "cancel" as const })),
    },
  };
}

const server = (capabilities: unknown) => ({ getClientCapabilities: () => capabilities }) as never;

describe("which era re-runs a call with the answer", () => {
  it("only the 2026 era does, so only there is a re-run not a new question", () => {
    assert.equal(makeClientIO("legacy", server({ elicitation: { form: {} } }), ctx() as never).replaysAnswers, false);
    assert.equal(makeClientIO("modern", server(undefined), ctx() as never).replaysAnswers, true);
  });
});

describe("the 2025-era client (legacy)", () => {
  it("can ask when the client declared a form capability, a bare one, or both modes; not when it declared nothing or url only", () => {
    for (const [cap, expected] of [[{ elicitation: { form: {} } }, true], [{ elicitation: {} }, true], [{ elicitation: { form: {}, url: {} } }, true], [{ elicitation: { url: {} } }, false], [{}, false], [undefined, false]] as const) {
      assert.equal(makeClientIO("legacy", server(cap), ctx() as never).canElicitForm, expected, JSON.stringify(cap));
    }
  });

  it("asks through elicitInput with the long human timeout and the call's abort signal, and maps every answer", async () => {
    let seen: { params: unknown; options: { timeout?: number; signal?: AbortSignal } | undefined } | undefined;
    const c = ctx({ elicitInput: async (params, options) => { seen = { params, options }; return { action: "accept", content: { typed: "old.example.com" } }; } });
    const io = makeClientIO("legacy", server({ elicitation: { form: {} } }), c as never);
    assert.deepEqual(await io.ask(REQUEST), { action: "accept", content: { typed: "old.example.com" } });
    assert.deepEqual(seen?.params, { mode: "form", message: "Delete?", requestedSchema: REQUEST.requestedSchema });
    assert.equal(seen?.options?.timeout, HUMAN_TIMEOUT_MS);
    assert.ok(HUMAN_TIMEOUT_MS >= 5 * 60_000);
    assert.equal(seen?.options?.signal, c.mcpReq.signal);
    for (const action of ["decline", "cancel"] as const) {
      const io2 = makeClientIO("legacy", server({ elicitation: { form: {} } }), ctx({ elicitInput: async () => ({ action }) }) as never);
      assert.deepEqual(await io2.ask(REQUEST), { action });
    }
  });

  it("tells a timeout from other failures, and never throws", async () => {
    const failing = (error: unknown) => makeClientIO("legacy", server({ elicitation: { form: {} } }), ctx({ elicitInput: async () => { throw error; } }) as never);
    assert.equal((await failing(new Error("Request timed out")).ask(REQUEST)).action, "timeout");
    assert.equal((await failing(Object.assign(new Error("x"), { code: "REQUEST_TIMEOUT" })).ask(REQUEST)).action, "timeout");
    assert.equal((await failing(Object.assign(new Error("x"), { code: -32001 })).ask(REQUEST)).action, "timeout");
    const other = await failing(new Error("connection closed")).ask(REQUEST);
    assert.equal(other.action, "error");
    assert.equal((await failing("a string").ask(REQUEST)).action, "error");
  });
});

describe("the 2026-era client (modern)", () => {
  const envelope = (elicitation: unknown): Record<string, unknown> => ({ "io.modelcontextprotocol/clientCapabilities": { elicitation } });

  it("reads the capability from the per-request envelope, not from the session", () => {
    assert.equal(makeClientIO("modern", server({ elicitation: { form: {} } }), ctx({ envelope: envelope(undefined) }) as never).canElicitForm, false);
    assert.equal(makeClientIO("modern", server(undefined), ctx({ envelope: envelope({ form: {} }) }) as never).canElicitForm, true);
    assert.equal(makeClientIO("modern", server(undefined), ctx({ envelope: envelope({ url: {} }) }) as never).canElicitForm, false);
    assert.equal(makeClientIO("modern", server(undefined), ctx() as never).canElicitForm, false);
  });

  it("needs input until the client has answered under this request's key", async () => {
    const io = makeClientIO("modern", server(undefined), ctx({ envelope: envelope({ form: {} }) }) as never);
    await assert.rejects(io.ask(REQUEST), (e: unknown) => e instanceof NeedInput && e.request === REQUEST);
    const wrongKey = makeClientIO("modern", server(undefined), ctx({ envelope: envelope({ form: {} }), inputResponses: { "approve-other": { action: "accept", content: { typed: "old.example.com" } } } }) as never);
    await assert.rejects(wrongKey.ask(REQUEST), NeedInput);
  });

  it("maps the answers; another kind of answer is an error, and garbage means no answer yet", async () => {
    const make = (value: unknown) =>
      makeClientIO("modern", server(undefined), ctx({ envelope: envelope({ form: {} }), inputResponses: { [REQUEST.key]: value } }) as never);
    assert.deepEqual(await make({ action: "accept", content: { typed: "old.example.com" } }).ask(REQUEST), { action: "accept", content: { typed: "old.example.com" } });
    assert.deepEqual(await make({ action: "decline" }).ask(REQUEST), { action: "decline" });
    assert.deepEqual(await make({ action: "cancel" }).ask(REQUEST), { action: "cancel" });
    assert.equal((await make({ role: "user", content: { type: "text", text: "x" }, model: "m" }).ask(REQUEST)).action, "error");
    assert.equal((await make({ roots: [] }).ask(REQUEST)).action, "error");
    for (const garbage of [{ messages: [] }, "accept", 7, null, [], { action: "approve" }]) {
      await assert.rejects(make(garbage).ask(REQUEST), NeedInput, JSON.stringify(garbage));
    }
  });
});
