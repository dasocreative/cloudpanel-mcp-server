import assert from "node:assert/strict";
import { describe, it } from "node:test";
import fc from "fast-check";
import { buildApprovalRequest, canElicitForm, evaluateDecision, type ApprovalInput } from "../src/policy/approval.ts";
import { protectedReason } from "../src/policy/protect.ts";
import { RateLimiter } from "../src/policy/rate.ts";
import { MAX_CONSUMED, PlanTokens, TOKEN_TTL_MS, canonicalJson } from "../src/policy/tokens.ts";
import { makeProfile } from "./helpers.ts";

const T0 = 1_700_000_000_000;

describe("canonicalJson", () => {
  it("does not depend on key order and skips undefined", () => {
    assert.equal(canonicalJson({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } }), canonicalJson({ a: { c: [3, { y: 2, z: 1 }], d: 2 }, b: 1 }));
    assert.equal(canonicalJson({ a: 1, b: undefined }), canonicalJson({ a: 1 }));
  });
  it("is sensitive to values, array order and types", () => {
    assert.notEqual(canonicalJson({ a: 1 }), canonicalJson({ a: "1" }));
    assert.notEqual(canonicalJson({ a: [1, 2] }), canonicalJson({ a: [2, 1] }));
    assert.notEqual(canonicalJson({ a: null }), canonicalJson({}));
    assert.notEqual(canonicalJson({ a: true }), canonicalJson({ a: "true" }));
  });
  it("property: equal objects built in any key order give equal strings", () => {
    fc.assert(
      fc.property(fc.dictionary(fc.string({ maxLength: 6 }), fc.oneof(fc.integer(), fc.string({ maxLength: 6 }), fc.boolean())), (obj) => {
        const reversed = Object.fromEntries(Object.entries(obj).reverse());
        assert.equal(canonicalJson(obj), canonicalJson(reversed));
      }),
      { numRuns: 200 },
    );
  });
});

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

describe("plan tokens", () => {
  const binding = canonicalJson({ tool: "clp_site_delete", profile: "p", args: { domainName: "a.example.com" } });

  it("verify for the binding they were issued for, once consumed they are dead", () => {
    const tokens = new PlanTokens({ now: () => T0 });
    const { token, expiresInSeconds } = tokens.issue(binding);
    assert.equal(expiresInSeconds, TOKEN_TTL_MS / 1000);
    const verdict = tokens.verify(token, binding);
    assert.ok(verdict.ok);
    if (!verdict.ok) return;
    assert.ok(tokens.verify(token, binding).ok, "verifying does not consume");
    assert.equal(tokens.consume(verdict.nonce), true);
    assert.equal(tokens.consume(verdict.nonce), false);
    const again = tokens.verify(token, binding);
    assert.ok(!again.ok && /already used/.test(again.reason));
  });

  it("refuse another binding, another process, an expired token, and every tampering", () => {
    let now = T0;
    const tokens = new PlanTokens({ now: () => now });
    const { token } = tokens.issue(binding);
    const other = canonicalJson({ tool: "clp_site_delete", profile: "p", args: { domainName: "b.example.com" } });
    for (const wrong of [other, "", binding + " ", canonicalJson({ tool: "clp_site_delete", profile: "q", args: { domainName: "a.example.com" } })]) {
      assert.ok(!tokens.verify(token, wrong).ok);
    }
    assert.ok(!new PlanTokens({ now: () => now }).verify(token, binding).ok, "another process has another key");
    const [v, nonce, expiry, mac] = token.split(".");
    const tampered = [
      `v2.${nonce}.${expiry}.${mac}`,
      `${v}.${nonce?.replace(/.$/, nonce.endsWith("0") ? "1" : "0")}.${expiry}.${mac}`,
      `${v}.${nonce}.${Number(expiry) + 1}.${mac}`,
      `${v}.${nonce}.${expiry}.${mac?.replace(/.$/, mac.endsWith("A") ? "B" : "A")}`,
      `${v}.${nonce}.${expiry}.`,
      `${v}.${nonce}.${expiry}`,
      `${token}.extra`,
      // the same bytes spelt differently: flip a padding bit of the last base64url character
      `${v}.${nonce}.${expiry}.${mac?.replace(/.$/, (c) => B64URL[B64URL.indexOf(c) ^ 1] as string)}`,
      "",
      "v1...",
      "garbage",
    ];
    for (const bad of tampered) assert.ok(!tokens.verify(bad, binding).ok, bad);
    now += TOKEN_TTL_MS + 1;
    const expired = tokens.verify(token, binding);
    assert.ok(!expired.ok && /expired/.test(expired.reason));
  });

  it("still verifies on the last millisecond", () => {
    let now = T0;
    const tokens = new PlanTokens({ now: () => now });
    const { token } = tokens.issue(binding);
    now += TOKEN_TTL_MS;
    assert.ok(tokens.verify(token, binding).ok);
  });

  it("property: random strings never verify and never throw", () => {
    const tokens = new PlanTokens({ now: () => T0 });
    fc.assert(fc.property(fc.string({ unit: "binary", maxLength: 200 }), (text) => { assert.ok(!tokens.verify(text, binding).ok); }), { numRuns: 500 });
    fc.assert(fc.property(fc.stringMatching(/^v1\.[0-9a-f]{24}\.[0-9]{13}\.[A-Za-z0-9_-]{20,44}$/), (text) => { assert.ok(!tokens.verify(text, binding).ok); }), { numRuns: 300 });
  });

  it("derive gives stable, binding-specific keys", () => {
    const tokens = new PlanTokens();
    assert.equal(tokens.derive("approval", binding), tokens.derive("approval", binding));
    assert.notEqual(tokens.derive("approval", binding), tokens.derive("approval", binding + "x"));
    assert.notEqual(tokens.derive("approval", binding), tokens.derive("other", binding));
    assert.match(tokens.derive("approval", binding), /^[0-9a-f]{16}$/);
    assert.notEqual(new PlanTokens().derive("approval", binding), tokens.derive("approval", binding));
  });

  it("remembers a used token whatever the clock does: after its expiry, and when the clock steps back", () => {
    let now = T0;
    const tokens = new PlanTokens({ now: () => now });
    const token = tokens.issue(binding).token;
    const first = tokens.verify(token, binding);
    assert.ok(first.ok);
    if (first.ok) assert.equal(tokens.consume(first.nonce), true);
    now += 3 * TOKEN_TTL_MS;
    tokens.verify(tokens.issue(binding).token, binding);
    if (first.ok) assert.equal(tokens.consume(first.nonce), false, "still remembered after the expiry");
    now = T0; // the clock steps back: the token is within its lifetime again, but it is used up
    const again = tokens.verify(token, binding);
    assert.equal(again.ok, false);
    assert.match(again.ok ? "" : again.reason, /already used/);
  });

  it("says when a token lapses, from its form alone", () => {
    const tokens = new PlanTokens({ now: () => T0 });
    const issued = tokens.issue(binding).token;
    assert.equal(tokens.expiryOf(issued), T0 + TOKEN_TTL_MS);
    for (const bad of ["", "v1", "v1.a.b", "v1.abc.12.mac", "v1.abc.12345678901234567890.mac", "a.b.c.d.e", "v1.nonce.not-a-number.mac"]) assert.equal(tokens.expiryOf(bad), undefined, bad);
  });

  it("keeps at most MAX_CONSUMED used nonces, dropping the oldest first", () => {
    const tokens = new PlanTokens({ now: () => T0 });
    const nonces: string[] = [];
    for (let i = 0; i < MAX_CONSUMED + 5; i += 1) {
      const nonce = i.toString(16).padStart(24, "0");
      nonces.push(nonce);
      assert.equal(tokens.consume(nonce), true);
    }
    assert.equal(tokens.consume(nonces[MAX_CONSUMED + 4] as string), false, "the newest is remembered");
    assert.equal(tokens.consume(nonces[5] as string), false, "the sixth oldest is still remembered");
    assert.equal(tokens.consume(nonces[0] as string), true, "the oldest was dropped to stay within the bound");
  });
});

describe("rate limiter", () => {
  it("allows max hits per window, then says when to retry; check does not record", () => {
    let now = T0;
    const limiter = new RateLimiter(() => now);
    const limit = { max: 2, perMinutes: 10 };
    assert.ok(limiter.check("k", limit).ok);
    assert.ok(limiter.check("k", limit).ok);
    assert.ok(limiter.take("k", limit).ok);
    now += 60_000;
    assert.ok(limiter.take("k", limit).ok);
    const blocked = limiter.take("k", limit);
    assert.ok(!blocked.ok && blocked.retryAfterSeconds === 540);
    assert.ok(!limiter.check("k", limit).ok);
    now += 9 * 60_000;
    assert.ok(limiter.take("k", limit).ok, "the first hit left the window");
    assert.ok(!limiter.take("k", limit).ok);
  });
  it("keeps keys apart and a refused take records nothing", () => {
    const limiter = new RateLimiter(() => T0);
    assert.ok(limiter.take("a", { max: 1, perMinutes: 1 }).ok);
    assert.ok(limiter.take("b", { max: 1, perMinutes: 1 }).ok);
    assert.ok(!limiter.take("a", { max: 1, perMinutes: 1 }).ok);
    assert.ok(!limiter.take("a", { max: 1, perMinutes: 1 }).ok);
  });
});

describe("protected targets", () => {
  const profile = makeProfile({
    protect: { domains: ["panel.example.com", "*.prod.example.com", "www.shop.example.net"], siteUsers: ["panelsite"], databases: ["maindb"], panelUsers: ["owner"] },
  });
  const why = (kind: "domain" | "siteUser" | "database" | "panelUser", value: string): string | null => protectedReason(profile, { kind, value });

  it("protects exact domains with or without www in either direction", () => {
    for (const d of ["panel.example.com", "www.panel.example.com", "shop.example.net", "www.shop.example.net"]) assert.ok(why("domain", d) !== null, d);
  });
  it("a wildcard covers subdomains at any depth and the apex, but not look-alikes", () => {
    for (const d of ["a.prod.example.com", "a.b.prod.example.com", "prod.example.com", "www.prod.example.com"]) assert.ok(why("domain", d) !== null, d);
    for (const d of ["evilprod.example.com", "prod.example.com.evil.net", "example.com", "x.example.com", "pro.example.com"]) assert.equal(why("domain", d), null, d);
  });
  it("protects the listed site users, databases and panel users only", () => {
    assert.ok(why("siteUser", "panelsite") !== null);
    assert.equal(why("siteUser", "other"), null);
    assert.ok(why("database", "maindb") !== null);
    assert.equal(why("database", "maindb2"), null);
    assert.ok(why("panelUser", "owner") !== null);
    // names are matched without regard to case: failing closed costs nothing
    assert.ok(why("panelUser", "Owner") !== null);
    assert.ok(why("siteUser", "PanelSite") !== null);
    assert.ok(why("database", "MAINDB") !== null);
  });
  it("ignores every leading www., so www.www.example.com cannot claim the protected site's other form", () => {
    const protectedProfile = makeProfile({ protect: { domains: ["example.com", "*.prod.example.org"], siteUsers: [], databases: [], panelUsers: [] } });
    const reason = (value: string): string | null => protectedReason(protectedProfile, { kind: "domain", value });
    for (const d of ["example.com", "www.example.com", "www.www.example.com", "www.www.www.www.example.com", "prod.example.org", "www.www.prod.example.org", "www.www.a.prod.example.org"]) {
      assert.ok(reason(d) !== null, d);
    }
    for (const d of ["wwwexample.com", "www-example.com", "www.example.com.evil.net", "xwww.example.com", "ww.www.example.net"]) assert.equal(reason(d), null, d);
    const wwwEntry = makeProfile({ protect: { domains: ["www.example.com"], siteUsers: [], databases: [], panelUsers: [] } });
    assert.ok(protectedReason(wwwEntry, { kind: "domain", value: "www.www.example.com" }) !== null);
    assert.ok(protectedReason(wwwEntry, { kind: "domain", value: "example.com" }) !== null);
  });
  it("protects nothing in a profile with empty lists", () => {
    assert.equal(protectedReason(makeProfile(), { kind: "domain", value: "panel.example.com" }), null);
  });
});

describe("human approval", () => {
  const base: ApprovalInput = {
    key: "approve-0123456789abcdef", cls: "destructive", profile: "prod", summary: "DELETE the site old.example.com",
    command: "sudo -n /usr/bin/clpctl site:delete '--domainName=old.example.com' --force", effects: ["removes the files"], reversible: "none", target: "old.example.com", noun: "domain",
  };

  it("builds a typed-target question for destructive and admin, a tick box for write", () => {
    const typed = buildApprovalRequest(base);
    assert.equal(typed.kind, "type-target");
    assert.equal(typed.target, "old.example.com");
    assert.deepEqual(typed.requestedSchema.required, ["typed"]);
    assert.match(typed.message, /profile "prod" \| DESTRUCTIVE/);
    assert.match(typed.message, /Command run on the server: sudo -n/);
    assert.match(typed.message, /type the domain name exactly: old\.example\.com/);
    assert.equal(buildApprovalRequest({ ...base, cls: "admin" }).kind, "type-target");
    const box = buildApprovalRequest({ ...base, cls: "write", target: undefined });
    assert.equal(box.kind, "type-target" === box.kind ? "x" : "confirm-box");
    assert.deepEqual(box.requestedSchema.required, ["approve"]);
    assert.equal(box.requestedSchema.properties["approve"]?.["default"], false);
  });
  it("refuses to build a destructive question without a target", () => {
    assert.throws(() => buildApprovalRequest({ ...base, target: undefined }));
    assert.throws(() => buildApprovalRequest({ ...base, target: "" }));
  });
  it("shows printable ASCII only", () => {
    const request = buildApprovalRequest({ ...base, summary: "x\u202e\u0000\u001b[31mred é 日" });
    assert.ok(!/[^\x20-\x7e\n]/.test(request.message));
  });

  it("approves only an explicit accept with exactly the right content", () => {
    const typed = buildApprovalRequest(base);
    assert.deepEqual(evaluateDecision(typed, { action: "accept", content: { typed: "old.example.com" } }), { approved: true });
    for (const content of [{ typed: "old.example.com " }, { typed: "OLD.example.com" }, { typed: "" }, { typed: 1 }, { typed: ["old.example.com"] }, { typed: null }, { approve: true }, {}, undefined]) {
      const v = evaluateDecision(typed, { action: "accept", content: content as never });
      assert.ok(!v.approved, JSON.stringify(content));
    }
    for (const action of ["decline", "cancel", "timeout", "error"] as const) {
      const v = evaluateDecision(typed, { action });
      assert.ok(!v.approved && v.decision === action);
    }
    const box = buildApprovalRequest({ ...base, cls: "write", target: undefined });
    assert.deepEqual(evaluateDecision(box, { action: "accept", content: { approve: true } }), { approved: true });
    for (const content of [{ approve: false }, { approve: "true" }, { approve: 1 }, {}, { typed: "x" }, undefined]) {
      assert.ok(!evaluateDecision(box, { action: "accept", content: content as never }).approved, JSON.stringify(content));
    }
  });
  it("property: no accept with a different typed value is ever approved", () => {
    const typed = buildApprovalRequest(base);
    fc.assert(
      fc.property(fc.anything({ maxDepth: 2 }), (value) => {
        fc.pre(value !== "old.example.com");
        assert.ok(!evaluateDecision(typed, { action: "accept", content: { typed: value } }).approved);
      }),
      { numRuns: 300 },
    );
  });

  it("canElicitForm: a form capability or a bare one asks; url-only and none do not", () => {
    assert.equal(canElicitForm({ form: {} }), true);
    assert.equal(canElicitForm({ form: {}, url: {} }), true);
    assert.equal(canElicitForm({}), true);
    assert.equal(canElicitForm({ url: {} }), false);
    for (const v of [undefined, null, 0, "form", false, []]) assert.equal(canElicitForm(v), v !== undefined && v !== null && typeof v === "object" ? Array.isArray(v) : false, String(v));
  });
});
