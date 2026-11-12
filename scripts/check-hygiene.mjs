#!/usr/bin/env node
/**
 * Repository hygiene: nothing personal, nothing secret, nothing hidden, nothing that runs on install.
 *
 *   node scripts/check-hygiene.mjs [--root DIR] [--history] [--patterns-file FILE]
 *
 * Generic checks always run over the tracked files (git ls-files):
 *   - invisible and bidirectional control characters ("Trojan Source") in text files
 *   - tracked .env files, build output, archives
 *   - install-time lifecycle scripts in package.json (also prepack, which npm runs for a git dependency)
 *   - binary files and files too large to scan (reported, not skipped: nothing may hide in them)
 *   - private-key headers and well-known token shapes
 *   - macOS and Windows home paths, public IPv4 addresses, e-mail addresses outside example domains
 * Private patterns (names, host names, domains of the maintainer) are NOT in this file: pass a file with
 * one case-insensitive regular expression per line (--patterns-file, or HYGIENE_PATTERNS_FILE). With
 * --history the commits' authors, committers and messages are checked too, and every identity must be
 * a placeholder (.invalid) or a GitHub noreply address. --history-content (which implies --history) also
 * scans every line ever added to any file for private patterns, keys, tokens, home paths and hidden
 * characters: a file deleted since is still published with the history. Run it before the first push.
 * Exit status 1 on any finding. Findings print file:line and the rule, never the private pattern.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const valueOf = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};
const root = resolve(valueOf("--root") ?? process.cwd());
const patternsFile = valueOf("--patterns-file") ?? process.env["HYGIENE_PATTERNS_FILE"];
const historyContent = args.includes("--history-content");
const history = args.includes("--history") || historyContent;

const findings = [];
const add = (where, rule, detail = "") => findings.push(`${where}: ${rule}${detail ? ` (${detail})` : ""}`);

function git(...argv) {
  return execFileSync("git", argv, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

const privatePatterns = [];
if (patternsFile !== undefined) {
  if (!existsSync(patternsFile)) {
    process.stderr.write(`patterns file not found: ${patternsFile}\n`);
    process.exit(2);
  }
  for (const line of readFileSync(patternsFile, "utf8").split("\n")) {
    const text = line.trim();
    if (text !== "" && !text.startsWith("#")) privatePatterns.push(new RegExp(text, "i"));
  }
}

// Written with property escapes so that this file itself holds no invisible character. Control characters (other than
// tab, line feed and carriage return), format characters (zero-width, bidirectional, TAG characters used to smuggle
// instructions to AI assistants), private-use and surrogate code points, line and paragraph separators, variation
// selectors and every default-ignorable code point (Hangul fillers, the combining grapheme joiner, ...).
const INVISIBLE = /(?![\t\n\r])[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}\p{Variation_Selector}\p{Default_Ignorable_Code_Point}]/u;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const TOKENS = [
  [/\bghp_[A-Za-z0-9]{30,}\b/, "a GitHub token"],
  [/\bgithub_pat_[A-Za-z0-9_]{30,}\b/, "a GitHub token"],
  [/\bnpm_[A-Za-z0-9]{30,}\b/, "an npm token"],
  [/\bAKIA[0-9A-Z]{16}\b/, "an AWS access key"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, "a Slack token"],
  [/\bsk-[A-Za-z0-9]{32,}\b/, "an API key"],
];
const HOME_PATH = /(\/Users\/[A-Za-z0-9._-]+\/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\)/;
const IPV4 = /(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/g;
const EMAIL = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})/g;
const OK_EMAIL_DOMAIN = /(^|\.)(example\.(com|org|net|invalid)|domain\.(com|io)|users\.noreply\.github\.com)$/i;
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"];
const MAX_SCAN_BYTES = 2 * 1024 * 1024;

function ipv4Allowed(ip) {
  const p = ip.split(".").map(Number);
  if (p.some((n) => n > 255)) return true; // not an address (a version string)
  if (p[0] === 127 || p[0] === 10 || p[0] === 0 || p[0] === 255) return true;
  if (p[0] === 192 && p[1] === 0 && p[2] === 2) return true;
  if (p[0] === 198 && p[1] === 51 && p[2] === 100) return true;
  if (p[0] === 203 && p[1] === 0 && p[2] === 113) return true;
  return false;
}

function scanText(where, text, { isTest, isLock }) {
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    const at = `${where}:${index + 1}`;
    if (INVISIBLE.test(line)) add(at, "an invisible or bidirectional control character");
    if (PRIVATE_KEY.test(line)) add(at, "a private key");
    for (const [re, what] of TOKENS) if (re.test(line)) add(at, `looks like ${what}`);
    if (HOME_PATH.test(line)) add(at, "a user home path");
    for (const re of privatePatterns) if (re.test(line)) add(at, "matches a private pattern");
    if (isLock) return;
    for (const m of line.matchAll(IPV4)) if (!ipv4Allowed(m[1])) add(at, "a public-looking IPv4 address", m[1]);
    if (!isTest) {
      for (const m of line.matchAll(EMAIL)) if (!OK_EMAIL_DOMAIN.test(m[1])) add(at, "an e-mail address outside the example domains", m[0].slice(0, 60));
    }
  });
}

if (!existsSync(join(root, ".git"))) {
  process.stderr.write(`${root} is not a git repository\n`);
  process.exit(2);
}

const tracked = git("ls-files", "-z").split("\0").filter(Boolean);
for (const file of tracked) {
  if (/(^|\/)\.env(\..*)?$/.test(file) && !file.endsWith(".env.example")) add(file, "a .env file is tracked");
  if (/(^|\/)(dist|coverage|node_modules)\//.test(file) || /\.(tgz|tar|zip|gz)$/.test(file)) add(file, "build output or an archive is tracked");
  const path = join(root, file);
  let size = 0;
  try {
    size = statSync(path).size;
  } catch {
    continue; // deleted in the working tree
  }
  if (size > MAX_SCAN_BYTES) {
    add(file, "is larger than 2 MiB and is not scanned: keep large files out of the repository");
    continue;
  }
  const buffer = readFileSync(path);
  if (buffer.includes(0)) {
    add(file, "is a binary file and is not scanned: keep binary files out of the repository");
    continue;
  }
  const text = buffer.toString("utf8");
  scanText(file, text, { isTest: /^test\//.test(file), isLock: file === "package-lock.json" });
  for (const re of privatePatterns) if (re.test(file)) add(file, "the file name matches a private pattern");
  if (file === "package.json") {
    try {
      const scripts = JSON.parse(text).scripts ?? {};
      for (const name of LIFECYCLE) if (name in scripts) add("package.json", `runs a "${name}" script on install`);
    } catch {
      add("package.json", "is not valid JSON");
    }
  }
}

if (history) {
  const log = git("log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e").split("\x1e").map((s) => s.trim()).filter(Boolean);
  for (const entry of log) {
    const [sha = "", an = "", ae = "", cn = "", ce = "", body = ""] = entry.split("\x1f");
    const at = `commit ${sha.slice(0, 10)}`;
    const placeholder = (email) => /(\.invalid|@users\.noreply\.github\.com)$/i.test(email);
    // GitHub itself is the committer of a merge or an edit made on its website
    const byGitHub = cn === "GitHub" && ce === ["noreply", "github.com"].join("@");
    if (!placeholder(ae) || !(placeholder(ce) || byGitHub)) add(at, "an author or committer address that is neither a placeholder nor a GitHub noreply address");
    // A GitHub noreply address is public by design, and so is the login inside it. The private patterns apply to the
    // message, to any other identity, and to a name beside a noreply address unless that name is the login itself.
    const login = (email) => /^(?:[0-9]+\+)?([^@+]+)@users\.noreply\.github\.com$/i.exec(email)?.[1]?.toLowerCase();
    const checked = (name, email) => {
      const own = login(email);
      if (own === undefined) return [name, email];
      return name.toLowerCase() === own ? [] : [name];
    };
    for (const re of privatePatterns) {
      const identity = checked(an, ae).concat(byGitHub ? [] : checked(cn, ce));
      if (identity.some((text) => re.test(text)) || re.test(body)) add(at, "matches a private pattern");
    }
    if (INVISIBLE.test(body)) add(at, "an invisible character in the message");
  }
  // names of files that ever existed
  const names = git("log", "--all", "--name-only", "--format=").split("\n").filter(Boolean);
  for (const name of new Set(names)) for (const re of privatePatterns) if (re.test(name)) add(`history:${name.slice(0, 40)}`, "a file name in the history matches a private pattern");
}

if (historyContent) {
  // every line ever added: a secret or a name committed once and deleted later is still published with the history
  const patch = git("log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=@@commit %H");
  let sha = "";
  for (const line of patch.split("\n")) {
    if (line.startsWith("@@commit ")) {
      sha = line.slice(9, 19);
    } else if (line.startsWith("+") && !line.startsWith("+++")) {
      const at = `history ${sha}`;
      const added = line.slice(1);
      if (PRIVATE_KEY.test(added)) add(at, "a private key was committed");
      for (const [re, what] of TOKENS) if (re.test(added)) add(at, `a line that looks like ${what} was committed`);
      if (HOME_PATH.test(added)) add(at, "a user home path was committed");
      if (INVISIBLE.test(added)) add(at, "an invisible or bidirectional control character was committed");
      for (const re of privatePatterns) if (re.test(added)) add(at, "a line matching a private pattern was committed");
    }
  }
}

if (findings.length > 0) {
  process.stderr.write(`${findings.length} hygiene finding(s):\n${[...new Set(findings)].slice(0, 100).map((f) => `  ${f}`).join("\n")}\n`);
  process.exit(1);
}
process.stdout.write(`hygiene ok: ${tracked.length} tracked files${historyContent ? ", history with contents" : history ? ", history" : ""}${privatePatterns.length > 0 ? `, ${privatePatterns.length} private patterns` : ""}\n`);
