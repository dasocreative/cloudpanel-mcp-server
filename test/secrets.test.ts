import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import fc from "fast-check";
import { AuditLog, THROTTLED_PER_MINUTE, reasonKind } from "../src/audit.ts";
import { sanitize } from "../src/exec/output.ts";
import { REDACTED, Redactor, isSecretOptionName, scrubPasswordOptions } from "../src/secrets/redact.ts";
import { PASSWORD_LENGTH, SecretsError, SecretsStore, generatePassword } from "../src/secrets/store.ts";
import { IS_WINDOWS, shortTmp } from "./helpers.ts";

const mode = (path: string): number => statSync(path).mode & 0o777;

describe("generatePassword", () => {
  it("has 32 characters from [A-Za-z0-9] and does not repeat", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i += 1) {
      const p = generatePassword();
      assert.equal(p.length, PASSWORD_LENGTH);
      assert.match(p, /^[A-Za-z0-9]{32}$/);
      seen.add(p);
    }
    assert.equal(seen.size, 2000);
  });
  it("uses all 62 symbols roughly evenly", () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 3000; i += 1) for (const ch of generatePassword()) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    assert.equal(counts.size, 62);
    const expected = (3000 * 32) / 62;
    for (const [ch, n] of counts) assert.ok(n > expected * 0.85 && n < expected * 1.15, `${ch}: ${n} vs ${expected}`);
  });
});

describe("SecretsStore", { skip: IS_WINDOWS }, () => {
  const request = { kind: "site" as const, target: "shop.example.com", account: "shop", option: "siteUserPassword" };
  const fixed = (): Date => new Date("2026-01-02T03:04:05.678Z");

  it("writes a 0600 file in a 0700 directory before anything runs, and returns its path", () => {
    const state = shortTmp();
    const store = new SecretsStore(state, "prod", fixed);
    const r = store.reserve(request, "SECRET-PASSWORD-12345678", "cmd");
    assert.equal(mode(r.path), 0o600);
    assert.equal(mode(join(state, "secrets", "prod")), 0o700);
    assert.equal(mode(join(state, "secrets")), 0o700);
    assert.equal(mode(state), 0o700);
    const body = JSON.parse(readFileSync(r.path, "utf8"));
    assert.equal(body.password, "SECRET-PASSWORD-12345678");
    assert.equal(body.profile, "prod");
    assert.equal(body.account, "shop");
    assert.match(r.path, /site-shop\.example\.com-20260102T030405678Z-[0-9a-f]{6}\.json$/);
    assert.equal(r.commit(true), r.path);
  });
  it("never overwrites: two reservations for the same target get different files", () => {
    const store = new SecretsStore(shortTmp(), "prod", fixed);
    const a = store.reserve(request, "AAAAAAAAAAAA", "c");
    const b = store.reserve(request, "BBBBBBBBBBBB", "c");
    assert.notEqual(a.path, b.path);
    assert.equal(JSON.parse(readFileSync(a.path, "utf8")).password, "AAAAAAAAAAAA");
  });
  it("never overwrites an existing file, even when a name collides", () => {
    const state = shortTmp();
    const store = new SecretsStore(state, "prod", fixed, () => "aaaaaa");
    const first = store.reserve(request, "FIRST-PASSWORD-1234567", "c");
    assert.throws(() => store.reserve(request, "SECOND-PASSWORD-123456", "c"), SecretsError);
    assert.equal(JSON.parse(readFileSync(first.path, "utf8")).password, "FIRST-PASSWORD-1234567");
    const captured = store.capture({ kind: "master-db", target: "credentials" }, "one", "c");
    assert.throws(() => store.capture({ kind: "master-db", target: "credentials" }, "two", "c"), SecretsError);
    assert.equal(JSON.parse(readFileSync(captured, "utf8")).output, "one");
  });
  it("renames the file when the command failed, keeping the password for diagnosis", () => {
    const state = shortTmp();
    const r = new SecretsStore(state, "prod", fixed).reserve(request, "SECRET-PASSWORD-12345678", "c");
    const original = r.path;
    const moved = r.commit(false);
    assert.match(moved, /\.failed\.json$/);
    assert.ok(!existsSync(original) && existsSync(moved));
    assert.equal(mode(moved), 0o600);
    assert.deepEqual(readdirSync(join(state, "secrets", "prod")), [moved.split("/").pop()]);
  });
  it("discard removes the file", () => {
    const r = new SecretsStore(shortTmp(), "prod", fixed).reserve(request, "SECRET-PASSWORD-12345678", "c");
    r.discard();
    assert.ok(!existsSync(r.path));
  });
  it("refuses targets and profiles that are not safe file names", () => {
    for (const target of ["../x", "a/b", "", ".", "..", "a\0b", "a b", "a;b", "x".repeat(129)]) {
      assert.throws(() => new SecretsStore(shortTmp(), "prod").reserve({ ...request, target }, "P", "c"), SecretsError, JSON.stringify(target));
    }
    for (const profile of ["../x", "a/b", ""]) {
      assert.throws(() => new SecretsStore(shortTmp(), profile).reserve(request, "P", "c"), SecretsError, JSON.stringify(profile));
    }
  });
  it("repairs loose permissions on an existing directory", () => {
    const state = shortTmp();
    mkdirSync(join(state, "secrets", "prod"), { recursive: true, mode: 0o755 });
    chmodSync(join(state, "secrets", "prod"), 0o755);
    new SecretsStore(state, "prod").reserve(request, "SECRET-PASSWORD-12345678", "c");
    assert.equal(mode(join(state, "secrets", "prod")), 0o700);
  });
  it("capture writes output that must not be shown to a 0600 file", () => {
    const state = shortTmp();
    const path = new SecretsStore(state, "prod", fixed).capture({ kind: "master-db", target: "credentials" }, "host|user|PASSWORD", "cmd");
    assert.equal(mode(path), 0o600);
    assert.equal(JSON.parse(readFileSync(path, "utf8")).output, "host|user|PASSWORD");
  });
});

describe("Redactor", () => {
  it("removes remembered secrets everywhere in a text, and any --*password*=value", () => {
    const r = new Redactor();
    r.add("SECRET-PASSWORD-12345678");
    assert.equal(r.scrub("a SECRET-PASSWORD-12345678 b SECRET-PASSWORD-12345678"), `a ${REDACTED} b ${REDACTED}`);
    assert.equal(r.scrub("--siteUserPassword=hunter2 x"), `--siteUserPassword=${REDACTED} x`);
    assert.equal(r.scrub("--password 'abc' x"), `--password '${REDACTED}' x`);
    assert.equal(r.scrub("--databaseUserPassword='p@ss' y"), `--databaseUserPassword='${REDACTED}' y`);
    assert.equal(r.scrub("nothing to see"), "nothing to see");
  });
  it("scrubs the password options the way the old pattern did, on the cases that matter", () => {
    const cases: [string, string][] = [
      ["--db-password=abc rest", `--db-password=${REDACTED} rest`],
      ["--PASSWORD abc", `--PASSWORD ${REDACTED}`],
      ["--databaseUserPassword 'p w'", `--databaseUserPassword '${REDACTED}'`],
      ['--password "abc def ghi" next', `--password "${REDACTED}" next`],
      ["--password='abc def ghi'", `--password='${REDACTED}'`],
      ["--password = Secret99 rest", `--password = ${REDACTED} rest`],
      ["--password =Secret99", `--password =${REDACTED}`],
      ["--password\n--other=1", "--password\n--other=1"],
      ["--password 'unclosed value", `--password '${REDACTED}`],
      ["--password=\\\"my secret pass\\\" tail", `--password=\\\"${REDACTED}\\\" tail`],
      ["--password=\\'my secret\\' tail", `--password=\\'${REDACTED}\\' tail`],
      ["--password=abc'def tail", `--password=${REDACTED} tail`],
      ['--password=abc"def tail', `--password=${REDACTED} tail`],
      ["--password=ab\\\"cd tail", `--password=${REDACTED} tail`],
      ["\u0130\u0130\u0130\u0130 --db-password=OtherSecret99 tail", `\u0130\u0130\u0130\u0130 --db-password=${REDACTED} tail`],
      ["\u212a\u212a --PASSWORD=Other99", `\u212a\u212a --PASSWORD=${REDACTED}`],
      ["--newPasswordRepeat=x\n--password=y", `--newPasswordRepeat=${REDACTED}\n--password=${REDACTED}`],
      ["--password=", "--password="],
      ["--password", "--password"],
      ["password=abc", "password=abc"],
      ["the password is abc", "the password is abc"],
      ["-password=abc", "-password=abc"],
      ["--passwordless=1", `--passwordless=${REDACTED}`],
    ];
    for (const [input, expected] of cases) assert.equal(scrubPasswordOptions(input), expected, input);
  });
  it("removes escape sequences and invisible characters first, so a secret split by them cannot be put back together by the cleaning that follows", () => {
    const r = new Redactor();
    const secret = "Abcdefghijklmnopqrstuvwxyz012345";
    r.add(secret);
    const pieces = [
      `x ${secret.slice(0, 10)}\u200b${secret.slice(10)} y`,
      `x ${secret.slice(0, 10)}\u001b[1m${secret.slice(10)} y`,
      `x ${secret.slice(0, 4)}\u2060${secret.slice(4, 8)}\u202e${secret.slice(8, 20)}\u{e0041}${secret.slice(20)} y`,
      `x ${secret.slice(0, 5)}\u034f${secret.slice(5)} y`,
      `x ${secret.slice(0, 5)}\u3164${secret.slice(5)} y`,
      `x ${secret.slice(0, 5)}\u001b]0;title\u0007${secret.slice(5)} y`,
    ];
    for (const text of pieces) {
      const once = r.scrub(text);
      assert.ok(!once.includes(secret), JSON.stringify(text));
      assert.equal(once, `x ${REDACTED} y`, JSON.stringify(text));
      assert.equal(sanitize(r.scrub(text)), once, "cleaning afterwards puts nothing back");
    }
    // the option scrub too: the word split by an invisible character
    assert.equal(r.scrub("--pass\u200bword=OtherSecret99"), `--password=${REDACTED}`);
  });
  it("scrubs text from a hostile server in linear time", () => {
    for (const hostile of ["-".repeat(300_000), "--password".repeat(30_000), `${"--a".repeat(100_000)}password`, "password".repeat(60_000), `--password=${"x".repeat(500_000)}`, "--password '".repeat(30_000), '--password "'.repeat(30_000), `--password '${"y".repeat(500_000)}`, "--password ".repeat(50_000), "--password =".repeat(50_000)]) {
      const started = Date.now();
      scrubPasswordOptions(hostile);
      new Redactor().scrub(hostile);
      assert.ok(Date.now() - started < 2000, `${hostile.slice(0, 20)}... took ${Date.now() - started} ms`);
    }
  });
  it("property: the value after a password option never survives", () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[A-Za-z]{0,12}$/),
        fc.stringMatching(/^[A-Za-z]{0,12}$/),
        fc.constantFrom("=", " "),
        fc.stringMatching(/^[0-9][0-9!#%&*+./:;<>?@^_~-]{3,39}$/),
        (before, after, separator, value) => {
          const out = scrubPasswordOptions(`x --${before}Password${after}${separator}${value} y`);
          assert.ok(!out.includes(value), out);
          assert.ok(out.includes(REDACTED), out);
        },
      ),
      { numRuns: 300 },
    );
  });
  it("ignores secrets shorter than 8 characters (they would blank ordinary text)", () => {
    const r = new Redactor();
    r.add("abc");
    assert.equal(r.scrub("abc def"), "abc def");
  });
  it("displayToken hides secret options by name or by value", () => {
    const r = new Redactor();
    r.add("SECRET-PASSWORD-12345678");
    assert.equal(r.displayToken("--password=whatever"), `--password=${REDACTED}`);
    assert.equal(r.displayToken("--userName=SECRET-PASSWORD-12345678"), `--userName=${REDACTED}`);
    assert.equal(r.displayToken("--domainName=a.example.com"), "--domainName=a.example.com");
    assert.ok(isSecretOptionName("databaseUserPassword") && isSecretOptionName("PASSWORD") && !isSecretOptionName("userName"));
  });
  it("property: no remembered secret survives scrubbing", () => {
    const r = new Redactor();
    r.add("Zq9Xk2Lm8Vb4Nc7Rt1Yw5Hj3Df6Gs0Ap");
    fc.assert(
      fc.property(fc.string({ maxLength: 50 }), fc.string({ maxLength: 50 }), (a, b) => {
        assert.ok(!r.scrub(`${a}Zq9Xk2Lm8Vb4Nc7Rt1Yw5Hj3Df6Gs0Ap${b}`).includes("Zq9Xk2Lm8Vb4Nc7Rt1Yw5Hj3Df6Gs0Ap"));
      }),
      { numRuns: 200 },
    );
  });
});

describe("AuditLog", () => {
  const fixed = (): Date => new Date("2026-01-02T03:04:05.000Z");

  it("appends one JSON line per event with a timestamp, in a 0600 file", { skip: IS_WINDOWS }, () => {
    const state = shortTmp();
    const log = new AuditLog(state, new Redactor(), fixed);
    log.record({ event: "start", tool: "clp_site_add_static", profile: "p", class: "write", command: "x" });
    log.record({ event: "end", tool: "clp_site_add_static", exitCode: 0, ok: true, durationMs: 12 });
    const lines = readFileSync(log.path, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.deepEqual(lines[0], { time: "2026-01-02T03:04:05.000Z", event: "start", tool: "clp_site_add_static", profile: "p", class: "write", command: "x" });
    assert.equal(lines[1].exitCode, 0);
    assert.equal(mode(log.path), 0o600);
    assert.equal(mode(state), 0o700);
  });
  it("redacts every string and bounds its length", () => {
    const redactor = new Redactor();
    redactor.add("SECRET-PASSWORD-12345678");
    const log = new AuditLog(shortTmp(), redactor);
    log.record({ event: "refused", reason: "bad SECRET-PASSWORD-12345678 and --password=abc", note: "y".repeat(5000) });
    const line = JSON.parse(readFileSync(log.path, "utf8"));
    assert.ok(!JSON.stringify(line).includes("SECRET-PASSWORD-12345678"));
    assert.ok(!JSON.stringify(line).includes("abc"));
    assert.equal(line.note.length, 2000);
  });
  it("bounds the records a model can cause at will: refusals, dry runs and reads are written at most 120 a minute each", () => {
    const state = shortTmp();
    let clock = Date.parse("2026-01-02T03:04:00.000Z");
    const log = new AuditLog(state, new Redactor(), () => new Date(clock));
    const lines = (): Record<string, unknown>[] => readFileSync(join(state, "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
    for (let i = 0; i < 500; i += 1) log.record({ event: "refused", tool: "clp_x", reason: `no ${i}` });
    for (let i = 0; i < 500; i += 1) log.record({ event: "plan", tool: "clp_x", class: "destructive" });
    for (let i = 0; i < 500; i += 1) log.record({ event: "end", tool: "clp_user_list", class: "read", ok: true });
    const kinds = (event: string): number => lines().filter((l) => l["event"] === event).length;
    assert.equal(kinds("refused"), THROTTLED_PER_MINUTE);
    assert.equal(kinds("plan"), THROTTLED_PER_MINUTE);
    assert.equal(lines().filter((l) => l["event"] === "end").length, THROTTLED_PER_MINUTE);
    assert.equal(kinds("note"), 3, "one note per kind says that the rest are counted, not written");
    assert.ok(lines().filter((l) => l["event"] === "note").every((l) => /counted, not written/.test(String(l["note"]))));
    // the records that matter are never held back, however many of the others there are
    for (let i = 0; i < 300; i += 1) {
      log.record({ event: "start", tool: "clp_site_delete", class: "destructive" });
      log.record({ event: "approval", tool: "clp_site_delete", class: "destructive", decision: "accept" });
      log.record({ event: "end", tool: "clp_site_delete", class: "destructive", ok: true });
    }
    assert.equal(kinds("start"), 300);
    assert.equal(kinds("approval"), 300);
    assert.equal(lines().filter((l) => l["event"] === "end" && l["class"] === "destructive").length, 300);
    // the next minute starts afresh and says how many were dropped
    clock += 60_000;
    log.record({ event: "refused", tool: "clp_x", reason: "again" });
    assert.equal(kinds("refused"), THROTTLED_PER_MINUTE + 1);
    const notes = lines().filter((l) => l["event"] === "note").map((l) => String(l["note"]));
    assert.ok(notes.some((n) => /^380 "refused::other" records were not written in the minute that began 2026-01-02T03:04Z/.test(n)), JSON.stringify(notes));
  });

  it("a flood of one kind of refusal cannot hide a refusal of another kind", () => {
    const state = shortTmp();
    const log = new AuditLog(state, new Redactor(), fixed);
    const lines = (): Record<string, unknown>[] => readFileSync(join(state, "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
    for (let i = 0; i < 400; i += 1) log.record({ event: "refused", tool: "clp_site_delete", class: "destructive", reason: `invalid arguments: domainName: ${i}` });
    const important: [string, string][] = [
      ["protected", "the domain panel.example.com is protected in profile \"p\" (protect.domains): it cannot be changed through this server"],
      ["token", "the planToken does not belong to this tool, profile and these arguments"],
      ["class", 'the profile "p" does not allow destructive tools (the operator enables them in the profile\'s allow list)'],
      ["rate", "rate limit reached for destructive tools in profile \"p\""],
      ["password", "passwords are never parameters of any tool"],
      ["unavailable", "this server's clpctl does not list the command site:delete"],
      ["internal", "internal error: the option domainName does not satisfy its type"],
    ];
    for (const [, reason] of important) log.record({ event: "refused", tool: "clp_site_delete", class: "destructive", reason });
    const written = lines().filter((l) => l["event"] === "refused").map((l) => String(l["reason"]));
    for (const [kind, reason] of important) assert.ok(written.includes(reason), `${kind}: ${reason}`);
    assert.equal(written.filter((r) => r.startsWith("invalid arguments")).length, THROTTLED_PER_MINUTE);
  });

  it("classifies refusals into a small fixed set of kinds", () => {
    const cases: [string | undefined, string][] = [
      ["invalid arguments: x", "invalid"], ["unknown tool", "invalid"], ["no such profile (call clp_server_info to see the configured ones)", "invalid"],
      ["passwords are never parameters of any tool", "password"],
      ['the profile "p" does not allow write tools (the operator ...)', "class"],
      ["the site user shop is protected in profile \"p\"", "protected"], ["the domain a.example.com is protected in profile \"p\"", "protected"],
      ["the planToken was already used: run a dry run again", "token"], ["the planToken has expired", "token"],
      ["rate limit reached for write tools", "rate"], ["too many approval questions for profile", "rate"], ["another approval question is already waiting", "rate"],
      ["no human approval is possible: this MCP client does not support elicitation forms", "unavailable"],
      ["this server's clpctl does not list the command x", "unavailable"],
      ["internal error: boom", "internal"], ["the human declined", "other"], [undefined, "other"], ["", "other"],
    ];
    for (const [reason, kind] of cases) assert.equal(reasonKind(reason), kind, String(reason));
  });

  it("bounds the approval records of a client that cannot ask, too", () => {
    const state = shortTmp();
    const log = new AuditLog(state, new Redactor(), fixed);
    for (let i = 0; i < 1000; i += 1) log.record({ event: "approval", tool: "clp_site_add_static", class: "write", decision: "unsupported", reason: "the client cannot show an approval form" });
    log.record({ event: "approval", tool: "clp_site_delete", class: "destructive", decision: "accept" });
    log.record({ event: "approval", tool: "clp_site_delete", class: "destructive", decision: "decline" });
    const lines = readFileSync(join(state, "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(lines.filter((l) => l["decision"] === "unsupported").length, THROTTLED_PER_MINUTE);
    assert.equal(lines.filter((l) => l["decision"] === "accept").length, 1, "a real decision is never held back");
    assert.equal(lines.filter((l) => l["decision"] === "decline").length, 1);
  });

  it("keeps one object per line even when a value contains a newline", () => {
    const log = new AuditLog(shortTmp(), new Redactor());
    log.record({ event: "refused", reason: "line1\nline2\r\n{\"event\":\"forged\"}" });
    const lines = readFileSync(log.path, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0] as string).event, "refused");
  });
  it("throws when the file cannot be written, so callers can refuse to run", () => {
    const state = shortTmp();
    mkdirSync(join(state, "audit.jsonl"));
    assert.throws(() => new AuditLog(state, new Redactor()).record({ event: "start" }));
    writeFileSync(join(state, "x"), "");
  });
});

describe("scrubbing a text that was scrubbed before, and a table (review round 4)", () => {
  it("leaves a value that is already the placeholder alone, so the quote or the JSON around it stays whole", () => {
    const same = [
      `clpctl user:add '--userName=jane' '--password=${REDACTED}' '--role=admin'`,
      `{"message":"failed: site:add:static --siteUserPassword=${REDACTED}","context":[],"level_name":"ERROR"}`,
      `{"line":"x \\"--password=${REDACTED}\\", y"}`,
      `--password=${REDACTED}`,
      `--password ${REDACTED} next`,
    ];
    for (const text of same) assert.equal(scrubPasswordOptions(text), text, text);
    const once = scrubPasswordOptions("clpctl site:add '--password=abc def' '--role=admin'");
    assert.equal(scrubPasswordOptions(once), once, "a second pass changes nothing");
    assert.doesNotThrow(() => JSON.parse(scrubPasswordOptions(same[1] as string)));
  });
  it("still replaces a value that only begins with the placeholder", () => {
    assert.equal(scrubPasswordOptions(`--password=${REDACTED}tail more`), `--password=${REDACTED} more`);
    assert.equal(scrubPasswordOptions(`--password=${REDACTED}"tail more`), `--password=${REDACTED} more`);
  });
  it("still takes an unknown value up to the next space, quotes inside it included", () => {
    assert.equal(scrubPasswordOptions(`--password=ab"cd',ef gh`), `--password=${REDACTED} gh`);
  });
  it("does not take the separator of a table for a value", () => {
    const row = "| jd | x--password | Doe | admin |";
    assert.equal(scrubPasswordOptions(row), row);
    assert.equal(scrubPasswordOptions("| x--password |"), "| x--password |");
    assert.equal(scrubPasswordOptions("--password |secret next"), `--password ${REDACTED} next`);
    assert.equal(scrubPasswordOptions("--password=| next"), `--password=${REDACTED} next`);
  });
});

describe("AuditLog: the count of records that were held back (review round 4)", () => {
  const read = (state: string): string[] =>
    readFileSync(join(state, "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => String((JSON.parse(l) as Record<string, unknown>)["note"] ?? ""));

  it("is written with the next record of any kind, and names the minute it belongs to", () => {
    const state = shortTmp();
    let clock = Date.parse("2026-01-02T10:00:00.000Z");
    const log = new AuditLog(state, new Redactor(), () => new Date(clock));
    for (let i = 0; i < 500; i += 1) log.record({ event: "refused", tool: "clp_x", reason: `no ${i}` });
    clock += 30 * 60_000;
    log.record({ event: "start", tool: "clp_site_delete", class: "destructive" });
    const notes = read(state).filter((n) => n !== "");
    assert.ok(notes.some((n) => /^380 "refused::other" records were not written in the minute that began 2026-01-02T10:00Z/.test(n)), JSON.stringify(notes));
    // said once
    log.record({ event: "refused", tool: "clp_x", reason: "later" });
    assert.equal(read(state).filter((n) => n.startsWith("380 ")).length, 1);
  });
  it("is written at shutdown for the minute that is still running", () => {
    const state = shortTmp();
    const log = new AuditLog(state, new Redactor(), () => new Date("2026-01-02T10:00:30.000Z"));
    for (let i = 0; i < THROTTLED_PER_MINUTE + 10; i += 1) log.record({ event: "plan", tool: "clp_x", class: "destructive" });
    assert.ok(!read(state).some((n) => n.startsWith("10 ")));
    log.flush();
    assert.ok(read(state).some((n) => /^10 "plan:destructive" records were not written in the minute that began 2026-01-02T10:00Z/.test(n)), JSON.stringify(read(state)));
    log.flush();
    assert.equal(read(state).filter((n) => n.startsWith("10 ")).length, 1, "nothing is said twice");
  });
});
