import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import fc from "fast-check";
import { assertCommandName, buildArgv, flagToken, optionToken, renderRemoteCommand, shellQuote } from "../src/exec/quote.ts";
import { RE, SOURCES, type PatternName } from "../src/validate/patterns.ts";
import { HOSTILE } from "./corpus.ts";
import { IS_WINDOWS, shortTmp, writeExecutable } from "./helpers.ts";

const SHELLS = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"].filter((s) => existsSync(s));

function printf(shell: string, quoted: string): string {
  return execFileSync(shell, ["-c", `printf '%s' ${quoted}`], { encoding: "utf8" });
}

describe("shellQuote", { skip: IS_WINDOWS }, () => {
  it("round-trips the hostile corpus through every available shell", () => {
    for (const shell of SHELLS) {
      for (const value of HOSTILE.filter((v) => !v.includes("\0"))) {
        assert.equal(printf(shell, shellQuote(value)), value, `${shell} ${JSON.stringify(value)}`);
      }
    }
  });

  it("property: round-trips arbitrary text built from shell-significant characters", () => {
    const unit = fc.oneof(fc.string({ unit: "grapheme-ascii", maxLength: 1 }), fc.constantFrom("'", '"', "\\", "$", "`", "\n", " ", ";", "&", "|", "*", "?", "[", "]", "{", "}", "(", ")", "<", ">", "~", "#", "!", "%", "é", "日", "😀", "\t"));
    fc.assert(
      fc.property(fc.array(unit, { maxLength: 40 }).map((a) => a.join("")), (value) => {
        for (const shell of SHELLS.slice(0, 2)) assert.equal(printf(shell, shellQuote(value)), value);
      }),
      { numRuns: 120 },
    );
  });

  it("refuses a NUL byte", () => {
    assert.throws(() => shellQuote("a\0b"));
  });
});

describe("tokens", () => {
  it("optionToken is one token and never lets a value become an option", () => {
    assert.equal(optionToken("domainName", "a.example.com"), "--domainName=a.example.com");
    assert.equal(optionToken("x", "--force"), "--x=--force");
    assert.equal(optionToken("x", ""), "--x=");
  });
  it("optionToken refuses bad names and control characters", () => {
    for (const name of ["", "a b", "a=b", "-a", "1a", "a-b", "a;b", "a".repeat(65)]) assert.throws(() => optionToken(name, "v"), /option name/, name);
    for (const value of ["a\nb", "a\rb", "a\0b", "a\u001bb", "a\u007fb"]) assert.throws(() => optionToken("n", value), /control/, JSON.stringify(value));
  });
  it("flagToken accepts only fixed-looking flags", () => {
    assert.equal(flagToken("--force"), "--force");
    for (const bad of ["force", "--Force", "--force=1", "-f", "--", "--a b", "--force;", ""]) assert.throws(() => flagToken(bad), /flag/, bad);
  });
  it("assertCommandName accepts clpctl command names only", () => {
    for (const ok of ["site:add:php", "db:add", "vhost-templates:list", "user:list"]) assert.equal(assertCommandName(ok), ok);
    for (const bad of ["", "Site:add", "a b", "x;y", "-x", ":x", "a".repeat(65), "x\n", "x$(id)"]) assert.throws(() => assertCommandName(bad), /command name/, JSON.stringify(bad));
  });
});

describe("buildArgv", () => {
  const base = { clpctlPath: "/usr/bin/clpctl", command: "db:add", tokens: ["--a=b"] };
  it("builds sudo -n <path> <command> <tokens>", () => {
    assert.deepEqual(buildArgv({ ...base, prefix: ["sudo", "-n"] }), ["sudo", "-n", "/usr/bin/clpctl", "db:add", "--a=b"]);
    assert.deepEqual(buildArgv({ ...base, prefix: [] }), ["/usr/bin/clpctl", "db:add", "--a=b"]);
    assert.deepEqual(buildArgv({ prefix: [], clpctlPath: "/usr/bin/clpctl", tokens: [] }), ["/usr/bin/clpctl"]);
  });
  it("refuses any prefix but `sudo -n`", () => {
    for (const prefix of [["bash", "-c"], ["sudo", "-u", "root"], ["env"], ["sudo", "-n", "x"], ["-n"], ["Sudo"], ["sudo;id"]]) {
      assert.throws(() => buildArgv({ ...base, prefix }), /prefix/, JSON.stringify(prefix));
    }
  });
  it("refuses a program path that is not a clean absolute path", () => {
    for (const clpctlPath of ["usr/bin/clpctl", "clpctl", "/usr/bin/../x", "/a b", "-x", "/a;b", "/a'b", "", "/"]) {
      assert.throws(() => buildArgv({ ...base, prefix: [], clpctlPath }), /path/, JSON.stringify(clpctlPath));
    }
  });
  it("refuses a bad command and a NUL in a token", () => {
    assert.throws(() => buildArgv({ ...base, prefix: [], command: "x;y" }));
    assert.throws(() => buildArgv({ ...base, prefix: [], tokens: ["--a=b\0"] }));
  });
});

describe("renderRemoteCommand", () => {
  it("leaves the fixed words bare and quotes every token", () => {
    const text = renderRemoteCommand({
      prefix: ["sudo", "-n"],
      clpctlPath: "/usr/bin/clpctl",
      command: "site:add:php",
      tokens: ["--domainName=www.example.com", "--vhostTemplate=PrestaShop 1.7", "--siteUserPassword=[REDACTED]"],
    });
    assert.equal(text, "sudo -n /usr/bin/clpctl site:add:php '--domainName=www.example.com' '--vhostTemplate=PrestaShop 1.7' '--siteUserPassword=[REDACTED]'");
  });
  it("escapes a single quote that should never reach it", () => {
    const text = renderRemoteCommand({ prefix: [], clpctlPath: "/usr/bin/clpctl", command: "x:y", tokens: ["--a=it's"] });
    assert.equal(text, "/usr/bin/clpctl x:y '--a=it'\\''s'");
  });
});

describe("what a remote shell makes of a rendered command", { skip: IS_WINDOWS }, () => {
  const dir = shortTmp("clpq-");
  // a program that prints each of its arguments, NUL-terminated
  const program = writeExecutable(dir, "echoargs", "#!/bin/sh\nprintf '%s\\0' \"$@\"\n");

  function run(shell: string, tokens: string[]): string[] {
    const command = renderRemoteCommand({ prefix: [], clpctlPath: program, command: "db:add", tokens });
    const out = execFileSync(shell, ["-c", command], { encoding: "utf8" });
    return out.split("\0").slice(0, -1);
  }

  it("delivers hostile-but-quoted values as single arguments", () => {
    for (const shell of SHELLS) {
      const values = HOSTILE.filter((v) => !v.includes("\0") && !/[\u0000-\u001f\u007f]/.test(v));
      const tokens = values.map((v, i) => optionToken(`o${String.fromCharCode(97 + (i % 26))}`, v));
      const got = run(shell, tokens);
      assert.deepEqual(got, ["db:add", ...tokens], shell);
    }
  });

  for (const name of Object.keys(SOURCES) as PatternName[]) {
    it(`property: valid ${name} values arrive unchanged in every shell`, () => {
      fc.assert(
        fc.property(fc.stringMatching(RE[name]), (value) => {
          const token = optionToken("value", value);
          for (const shell of SHELLS.slice(0, 2)) assert.deepEqual(run(shell, [token]), ["db:add", token]);
        }),
        { numRuns: 25 },
      );
    });
  }

  it("a program path inside the temp dir is clean (sanity for the rig)", () => {
    assert.ok(join(dir, "echoargs").startsWith("/tmp/") || join(dir, "echoargs").startsWith("/"));
  });
});
