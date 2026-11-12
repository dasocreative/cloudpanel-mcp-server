import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import fc from "fast-check";
import { MAX_STREAM_CHARS, extractServerMessage, parseTable, parseUsageListing, sanitize, truncate } from "../src/exec/output.ts";
import { ROOT } from "./helpers.ts";

const FIX = join(ROOT, "test", "fixtures", "recorded");
const read = (name: string): string => readFileSync(join(FIX, name), "utf8");

describe("sanitize", () => {
  it("removes ANSI sequences, OSC titles and control characters, keeping newlines and tabs", () => {
    assert.equal(sanitize("\u001b[31mred\u001b[0m ok"), "red ok");
    assert.equal(sanitize("\u001b[1;32;40mx\u001b[K"), "x");
    assert.equal(sanitize("a\u001b]0;evil title\u0007b"), "ab");
    assert.equal(sanitize("a\u001b]8;;http://x\u001b\\link\u001b]8;;\u001b\\"), "alink");
    assert.equal(sanitize("a\u0000b\u0007c\u007fd\u0085e"), "abcde");
    assert.equal(sanitize("line1\nline2\tTab\r\n"), "line1\nline2\tTab\r\n");
  });
  it("removes bidirectional overrides, zero-width characters and the byte order mark", () => {
    assert.equal(sanitize("a\u202eb\u202ac\u2066d\u2069e\u200bf\u200fg\ufeffh"), "abcdefgh");
  });
  it("removes tag characters, variation selectors, private-use, unassigned and separator code points, and keeps real text", () => {
    // ... and the default-ignorable ones that are not format characters: the combining grapheme joiner, Hangul and Khmer fillers
    const hidden = [0xe0041, 0xe0020, 0xe007f, 0xfe0f, 0xe0100, 0xe000, 0xf8ff, 0x2028, 0x2029, 0x00ad, 0x061c, 0x180e, 0x200c, 0x200d, 0x2060, 0x2064, 0xfff9, 0xffff, 0x0378, 0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x3164, 0xffa0];
    for (const cp of hidden) assert.equal(sanitize(`x${String.fromCodePoint(cp)}y`), "xy", `U+${cp.toString(16)}`);
    const text = "plain text, umlauts \u00e4\u00f6\u00fc, \u4e2d\u6587, emoji \u{1f600}";
    assert.equal(sanitize(text), text);
  });
  it("removes every default-ignorable code point (scanning the whole range)", () => {
    const pattern = /\p{Default_Ignorable_Code_Point}/u;
    const survivors: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const ch = String.fromCodePoint(cp);
      if (pattern.test(ch) && sanitize(`a${ch}b`) !== "ab") survivors.push(cp.toString(16));
    }
    assert.deepEqual(survivors, []);
  });
  it("property: the result never contains an escape or a control character other than \\n \\r \\t", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 200 }), (text) => {
        const out = sanitize(text);
        assert.ok(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(out), JSON.stringify(out));
      }),
      { numRuns: 500 },
    );
  });
});

describe("truncate", () => {
  it("keeps short text and bounds long text with a note", () => {
    assert.equal(truncate("abc", 10), "abc");
    const out = truncate("x".repeat(50), 10);
    assert.ok(out.startsWith("x".repeat(10)));
    assert.match(out, /\[truncated: 40 more characters not shown\]/);
    assert.equal(truncate("x".repeat(MAX_STREAM_CHARS)).length, MAX_STREAM_CHARS);
  });
  it("never cuts a surrogate pair in half", () => {
    const text = "a".repeat(9) + "😀" + "b".repeat(20);
    const out = truncate(text, 10);
    assert.ok(!/[\ud800-\udbff](?![\udc00-\udfff])/.test(out.split("\n")[0] ?? ""));
  });
});

describe("extractServerMessage", () => {
  const line = (message: unknown, level = "ERROR"): string => JSON.stringify({ message, context: [], level_name: level });
  it("finds the message of a JSON log line and its severity", () => {
    assert.deepEqual(extractServerMessage([`${line("databaseName: This value is not valid.")}\n\n [ERROR] x`]), { message: "databaseName: This value is not valid.", severe: true });
    assert.deepEqual(extractServerMessage([line("fyi", "INFO")]), { message: "fyi", severe: false });
    assert.equal(extractServerMessage([line("x", "critical")])?.severe, true);
  });
  it("prefers a severe line over an earlier harmless one, across streams", () => {
    assert.deepEqual(extractServerMessage([line("note", "INFO"), line("boom", "CRITICAL")]), { message: "boom", severe: true });
  });
  it("ignores text that is not a log line", () => {
    for (const text of ["", "plain", "{not json", "[1,2]", "{\"message\": 5}", "{\"message\": \"\"}", "null", "{\"level_name\":\"ERROR\"}"]) {
      assert.equal(extractServerMessage([text]), null, text);
    }
    assert.equal(extractServerMessage([`{"message":"${"x".repeat(100_001)}"}`]), null);
  });
  it("cleans and bounds the message", () => {
    const m = extractServerMessage([line(`\u001b[31m${"y".repeat(1000)}\u001b[0m`)]);
    assert.equal(m?.message.length, 400);
    assert.ok(!m?.message.includes("\u001b"));
  });
  it("property: never throws", () => {
    fc.assert(fc.property(fc.string({ unit: "binary", maxLength: 300 }), fc.string({ maxLength: 100 }), (a, b) => { extractServerMessage([a, b]); }), { numRuns: 500 });
    fc.assert(fc.property(fc.json(), (j) => { extractServerMessage([j]); }), { numRuns: 300 });
  });
});

describe("parseTable", () => {
  it("reads the recorded vhost-templates table", () => {
    const table = parseTable(read("vhost-templates-list.txt"));
    assert.deepEqual(table?.headers, ["Name", "Root Directory", "Type"]);
    assert.equal(table?.rows.length, 27);
    assert.deepEqual(table?.rows[0], ["CakePHP 5", "webroot", "System"]);
    assert.deepEqual(table?.rows.find((r) => r[0] === "Generic"), ["Generic", "", "System"]);
  });
  it("reads the user table layout", () => {
    const table = parseTable(read("user-list.txt"));
    assert.deepEqual(table?.headers, ["User Name", "First Name", "Last Name", "E-Mail", "Role", "Status"]);
    assert.equal(table?.rows.length, 2);
  });
  it("returns null for non-tables and bounds huge ones", () => {
    assert.equal(parseTable(""), null);
    assert.equal(parseTable("nothing here"), null);
    const rows = Array.from({ length: 5000 }, (_, i) => `| r${i} | x |`).join("\n");
    assert.equal(parseTable(`| a | b |\n${rows}`)?.rows.length, 500);
  });
  it("property: never throws", () => {
    fc.assert(fc.property(fc.string({ unit: "binary", maxLength: 300 }), (text) => { parseTable(text); }), { numRuns: 500 });
  });
});

describe("parseUsageListing", () => {
  const listing = parseUsageListing(read("usage-listing.txt"));
  const byName = new Map(listing.map((c) => [c.name, c.options]));

  it("reads the 28 commands of the recorded CloudPanel 2.5.4 listing", () => {
    assert.equal(listing.length, 28);
    assert.ok(byName.has("system:permissions:reset"));
    assert.ok(!byName.has("varnish-cache:purge"));
    assert.ok(byName.has("db:delete") && byName.has("cloudpanel:set:release-channel"));
  });
  it("reads the options of each example line", () => {
    assert.deepEqual(byName.get("site:add:php"), ["domainName", "phpVersion", "vhostTemplate", "siteUser", "siteUserPassword"]);
    assert.deepEqual(byName.get("site:delete"), ["domainName"]);
    assert.deepEqual(byName.get("user:list"), []);
    assert.deepEqual(byName.get("lets-encrypt:install:certificate"), ["domainName", "subjectAlternativeName"]);
    assert.deepEqual(byName.get("user:add"), ["userName", "email", "firstName", "lastName", "password", "role", "sites", "timezone", "status"]);
  });
  it("ignores headings and comment lines, and is not fooled by colours", () => {
    const coloured = read("usage-listing.txt").replace(/^ clpctl /gm, " \u001b[32mclpctl\u001b[0m ").replace(/^db$/m, "\u001b[33mdb\u001b[0m");
    assert.deepEqual(parseUsageListing(coloured).map((c) => c.name), listing.map((c) => c.name));
  });
  it("keeps only namespaced command names and bounds what it keeps", () => {
    assert.deepEqual(parseUsageListing("clpctl list\nclpctl help\nsome text\n"), []);
    assert.deepEqual(parseUsageListing("clpctl db:add --a=1 --b=2 --a=3").map((c) => c.options), [["a", "b"]]);
    const many = Array.from({ length: 1500 }, (_, i) => `clpctl x:c${i}`).join("\n");
    assert.equal(parseUsageListing(many).length, 1000);
    const options = Array.from({ length: 300 }, (_, i) => `--o${i}=1`).join(" ");
    assert.equal(parseUsageListing(`clpctl x:y ${options}`)[0]?.options.length, 100);
  });
  it("property: never throws, and every name it returns is well formed", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 400 }), (text) => {
        for (const c of parseUsageListing(text)) assert.match(c.name, /^[a-z][a-z0-9:_-]{0,63}$/);
      }),
      { numRuns: 500 },
    );
  });
});

describe("the helpers read the output as the server wrote it (review round 4)", () => {
  const line = (message: string): string => JSON.stringify({ message, context: [], level_name: "ERROR" });
  it("extractServerMessage scrubs the whole message before it cuts it", () => {
    const secret = "S3cretValue-0123456789";
    const scrub = (text: string): string => text.split(secret).join("[R]");
    const m = extractServerMessage([line(`${"a".repeat(390)}${secret}`)], scrub);
    assert.equal(m?.severe, true);
    assert.ok(m?.message.endsWith("[R]"), m?.message.slice(-30));
    assert.ok(!m?.message.includes("S3cret"));
  });
  it("extractServerMessage finds a line behind an escape sequence", () => {
    assert.equal(extractServerMessage([`\u001b[31m${line("boom")}\u001b[0m`])?.message, "boom");
  });
  it("parseTable cleans each cell before it cuts it", () => {
    const secret = "S3cretValue-0123456789";
    const table = parseTable(`| a |\n| ${"x".repeat(190)}${secret} |\n`, (cell) => cell.split(secret).join("[R]"));
    assert.ok(table?.rows[0]?.[0]?.endsWith("[R]"));
    assert.ok(!JSON.stringify(table).includes("S3cret"));
  });
});
