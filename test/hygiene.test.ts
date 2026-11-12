import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { IS_WINDOWS, ROOT, shortTmp } from "./helpers.ts";

const SCRIPT = join(ROOT, "scripts", "check-hygiene.mjs");
const hasGit = spawnSync("git", ["--version"]).status === 0;

function check(root: string, extra: string[] = []): { status: number | null; stderr: string; stdout: string } {
  const r = spawnSync(process.execPath, [SCRIPT, "--root", root, ...extra], { encoding: "utf8" });
  return { status: r.status, stderr: r.stderr, stdout: r.stdout };
}

function repo(files: Record<string, string>, identity = "Tester <tester@example.invalid>"): string {
  const dir = shortTmp("clph-");
  const git = (...a: string[]) => execFileSync("git", ["-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  git("init", "-q", "-b", "main");
  const [name = "t", email = "t@example.invalid"] = identity.replace(">", "").split(" <");
  git("config", "user.name", name);
  git("config", "user.email", email);
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, file)), { recursive: true });
    writeFileSync(join(dir, file), content);
  }
  git("add", "-A");
  git("commit", "-q", "-m", "test");
  return dir;
}

describe("the repository itself", { skip: !hasGit || IS_WINDOWS }, () => {
  it("passes the generic hygiene checks, history included", () => {
    const r = check(ROOT, ["--history"]);
    assert.equal(r.status, 0, r.stderr);
  });
});

describe("the hygiene script", { skip: !hasGit || IS_WINDOWS }, () => {
  const bad: [string, Record<string, string>, RegExp][] = [
    ["a bidirectional override", { "a.ts": "const x = 'a\u202eb';\n" }, /invisible or bidirectional/],
    ["a zero-width space", { "a.md": "hello\u200bworld\n" }, /invisible or bidirectional/],
    ["a tag character (ASCII smuggling)", { "a.md": `hello${String.fromCodePoint(0xe0041)}${String.fromCodePoint(0xe0042)}world\n` }, /invisible or bidirectional/],
    ["a word joiner", { "a.md": `hello${String.fromCodePoint(0x2060)}world\n` }, /invisible or bidirectional/],
    ["a variation selector", { "a.md": `hello${String.fromCodePoint(0xfe01)}world\n` }, /invisible or bidirectional/],
    ["a supplementary variation selector", { "a.md": `hello${String.fromCodePoint(0xe0100)}world\n` }, /invisible or bidirectional/],
    ["a Hangul filler", { "a.md": `hello${String.fromCodePoint(0x3164)}world\n` }, /invisible or bidirectional/],
    ["a combining grapheme joiner", { "a.md": `hello${String.fromCodePoint(0x034f)}world\n` }, /invisible or bidirectional/],
    ["a private-use character", { "a.md": `hello${String.fromCodePoint(0xe000)}world\n` }, /invisible or bidirectional/],
    ["a control character", { "a.md": `hello${String.fromCodePoint(0x0007)}world\n` }, /invisible or bidirectional/],
    ["a tracked .env file", { ".env": "A=1\n" }, /\.env file is tracked/],
    ["a nested .env.production", { "app/.env.production": "A=1\n" }, /\.env file is tracked/],
    ["tracked build output", { "dist/index.js": "x\n" }, /build output/],
    ["an archive", { "release.tgz": "x\n" }, /archive/],
    ["a postinstall script", { "package.json": JSON.stringify({ scripts: { postinstall: "node x.js" } }) }, /"postinstall" script/],
    ["a prepare script", { "package.json": JSON.stringify({ scripts: { prepare: "tsc" } }) }, /"prepare" script/],
    ["a prepack script (npm runs it for a git dependency)", { "package.json": JSON.stringify({ scripts: { prepack: "tsc" } }) }, /"prepack" script/],
    ["a binary file", { "logo.bin": "PNG\u0000\u0001\u0002" }, /binary file/],
    ["a file too large to scan", { "big.txt": "x".repeat(2 * 1024 * 1024 + 16) }, /larger than 2 MiB/],
    ["a private key", { "k.txt": `-----BEGIN ${"OPENSSH"} PRIVATE KEY-----\n` }, /private key/],
    ["a GitHub token", { "t.txt": `token ghp_${"a".repeat(36)}\n` }, /GitHub token/],
    ["an npm token", { "t.txt": `npm_${"A".repeat(36)}\n` }, /npm token/],
    ["a macOS home path", { "p.md": `see /${"Users"}/someone/project/x\n` }, /home path/],
    ["a Windows home path", { "p.md": "C:\\Users\\someone\\x\n" }, /home path/],
    ["a public IPv4 address", { "h.md": `ssh root@${["93", "184", "216", "34"].join(".")}\n` }, /IPv4/],
    ["an e-mail outside the examples", { "c.md": "write to someone@gmail.com\n" }, /e-mail/],
  ];
  for (const [name, files, pattern] of bad) {
    it(`flags ${name}`, () => {
      const r = check(repo(files));
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, pattern);
    });
  }

  it("accepts documentation addresses, example domains and the CloudPanel docs' own examples", () => {
    const r = check(repo({
      "ok.md": "ssh deploy@203.0.113.7 and 127.0.0.1 and 10.0.0.5 and 192.0.2.1 and 198.51.100.9\nmail john.doe@domain.com, a@example.org, 1234+me@users.noreply.github.com, root@evil.example.com\nversion 2.5.4.3.1 and 1.30\n",
      "package.json": JSON.stringify({ scripts: { build: "tsc", test: "node --test", prepublishOnly: "tsc" } }),
      "test/x.test.ts": "const mail = 'a@x.com';\n",
    }));
    assert.equal(r.status, 0, r.stderr);
  });

  it("applies private patterns from a file, case-insensitively, without printing them", () => {
    const dir = repo({ "notes.md": "contact the Maintainer-Secret-Name for access\n", "clean.md": "nothing\n" });
    const patterns = join(shortTmp("clph-"), "patterns.txt");
    writeFileSync(patterns, "# comment\nmaintainer-secret-name\n\n");
    const r = check(dir, ["--patterns-file", patterns]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /notes\.md:1: matches a private pattern/);
    assert.ok(!r.stderr.toLowerCase().includes("maintainer-secret-name"));
    assert.equal(check(repo({ "clean.md": "nothing\n" }), ["--patterns-file", patterns]).status, 0);
  });

  it("with --history refuses an identity that is not a placeholder or a GitHub noreply address", () => {
    assert.equal(check(repo({ "a.md": "x\n" }, "Real Person <real@gmail.com>"), ["--history"]).status, 1);
    assert.equal(check(repo({ "a.md": "x\n" }, "Name <12345+name@users.noreply.github.com>"), ["--history"]).status, 0);
    assert.equal(check(repo({ "a.md": "x\n" }, "Placeholder <x@example.invalid>"), ["--history"]).status, 0);
  });

  it("with --history, a private pattern does not apply to a GitHub noreply identity, only to the message and to other identities", () => {
    const patterns = join(shortTmp("clph-"), "patterns.txt");
    writeFileSync(patterns, "secretlogin\n");
    assert.equal(check(repo({ "a.md": "x\n" }, "secretlogin <12345+secretlogin@users.noreply.github.com>"), ["--history", "--patterns-file", patterns]).status, 0);
    assert.equal(check(repo({ "a.md": "x\n" }, "secretlogin <x@example.invalid>"), ["--history", "--patterns-file", patterns]).status, 1);
    const dir = repo({ "a.md": "x\n" }, "Name <12345+name@users.noreply.github.com>");
    writeFileSync(join(dir, "b.md"), "y\n");
    execFileSync("git", ["-c", "commit.gpgsign=false", "add", "-A"], { cwd: dir });
    execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "-q", "-m", "mentions secretlogin"], { cwd: dir });
    assert.equal(check(dir, ["--history", "--patterns-file", patterns]).status, 1, "the message is still checked");
  });

  it("with --history, a name beside a GitHub noreply address is checked unless it is the login in that address", () => {
    const patterns = join(shortTmp("clph-"), "patterns.txt");
    writeFileSync(patterns, "privatename\nsecretlogin\n");
    assert.equal(check(repo({ "a.md": "x\n" }, "Jane Privatename <123+login@users.noreply.github.com>"), ["--history", "--patterns-file", patterns]).status, 1);
    assert.equal(check(repo({ "a.md": "x\n" }, "SecretLogin <123+secretlogin@users.noreply.github.com>"), ["--history", "--patterns-file", patterns]).status, 0);
    assert.equal(check(repo({ "a.md": "x\n" }, "secretlogin <secretlogin@users.noreply.github.com>"), ["--history", "--patterns-file", patterns]).status, 0);
    assert.equal(check(repo({ "a.md": "x\n" }, "Jane Doe <123+login@users.noreply.github.com>"), ["--history", "--patterns-file", patterns]).status, 0);
  });

  it("with --history accepts GitHub itself as the committer (a merge made on the website), and only as the committer", () => {
    const github = ["noreply", "github.com"].join("@");
    const commitAs = (dir: string, env: Record<string, string>): void => {
      execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "merge"], { cwd: dir, env: { ...process.env, ...env } });
    };
    const merged = repo({ "a.md": "x\n" }, "Name <12345+name@users.noreply.github.com>");
    commitAs(merged, { GIT_COMMITTER_NAME: "GitHub", GIT_COMMITTER_EMAIL: github });
    assert.equal(check(merged, ["--history"]).status, 0);
    const other = repo({ "a.md": "x\n" }, "Name <12345+name@users.noreply.github.com>");
    commitAs(other, { GIT_COMMITTER_NAME: "Somebody", GIT_COMMITTER_EMAIL: github });
    assert.equal(check(other, ["--history"]).status, 1, "the address alone is not enough");
    const author = repo({ "a.md": "x\n" }, "Name <12345+name@users.noreply.github.com>");
    commitAs(author, { GIT_AUTHOR_NAME: "GitHub", GIT_AUTHOR_EMAIL: github });
    assert.equal(check(author, ["--history"]).status, 1, "not as the author");
  });

  it("with --history finds a private pattern in a commit message and in a deleted file's name", () => {
    const dir = repo({ "a.md": "x\n" });
    const g = (...a: string[]) => execFileSync("git", ["-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });
    writeFileSync(join(dir, "secret-host-name.txt"), "x\n");
    g("add", "-A");
    g("commit", "-q", "-m", "mention internal-server-7 here");
    g("rm", "-q", "secret-host-name.txt");
    g("commit", "-q", "-m", "remove");
    const patterns = join(shortTmp("clph-"), "patterns.txt");
    writeFileSync(patterns, "internal-server-7\nsecret-host-name\n");
    const r = check(dir, ["--history", "--patterns-file", patterns]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /commit [0-9a-f]{10}: matches a private pattern/);
    assert.match(r.stderr, /file name in the history/);
  });

  it("with --history scans every line ever added, also in a file deleted since", () => {
    const dir = repo({ "a.md": "x\n" });
    const g = (...a: string[]) => execFileSync("git", ["-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });
    const secrets: [string, string, RegExp][] = [
      ["a token", `token ghp_${"b".repeat(36)}\n`, /looks like a GitHub token was committed|a line that looks like a GitHub token/],
      ["a private key", `-----BEGIN ${"RSA"} PRIVATE KEY-----\n`, /a private key was committed/],
      ["a home path", `see /${"Users"}/someone/x\n`, /a user home path was committed/],
      ["a private name", "ask Internal-Person-Name\n", /a line matching a private pattern was committed/],
    ];
    const patterns = join(shortTmp("clph-"), "patterns.txt");
    writeFileSync(patterns, "internal-person-name\n");
    for (const [name, content, expected] of secrets) {
      writeFileSync(join(dir, "oops.txt"), content);
      g("add", "-A");
      g("commit", "-q", "-m", `add ${name}`);
      g("rm", "-q", "oops.txt");
      g("commit", "-q", "-m", `remove ${name}`);
      assert.equal(check(dir, []).status, 0, `${name}: the working tree is clean`);
      const r = check(dir, ["--history-content", "--patterns-file", patterns]);
      assert.equal(r.status, 1, name);
      assert.equal(check(dir, ["--history", "--patterns-file", patterns]).status, 0, `${name}: --history alone does not read file contents`);
      assert.match(r.stderr, expected, name);
      assert.match(r.stderr, /history [0-9a-f]{10}/);
      assert.ok(!r.stderr.toLowerCase().includes("internal-person-name"), "the private pattern is never printed");
      // rewrite the history so the next case starts clean
      g("reset", "-q", "--hard", "HEAD~2");
    }
    assert.equal(check(dir, ["--history-content", "--patterns-file", patterns]).status, 0, "clean again");
  });

  it("refuses to run outside a git repository", () => {
    assert.equal(check(shortTmp("clph-")).status, 2);
  });
});
