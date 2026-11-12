#!/usr/bin/env node
/**
 * Checks what `npm pack` would publish: only the allowed paths, nothing from tests, scripts, source or
 * configuration, no source maps, no dotfiles, and the executable bit on the gate and the inventory script.
 *   npm run check:pack
 */
import { execFileSync } from "node:child_process";

const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { encoding: "utf8", shell: process.platform === "win32" });
const entries = JSON.parse(out)[0].files;
const files = entries.map((f) => f.path);
// the scripts that run on a server must stay executable in the tarball
const mustBeExecutable = ["hardening/cloudpanel-mcp-gate.sh", "hardening/cloudpanel-mcp-setup.sh", "inventory/cloudpanel-mcp-inventory"];
const notExecutable = entries.filter((f) => mustBeExecutable.includes(f.path) && (f.mode & 0o111) === 0).map((f) => f.path);
const allowed = [
  /^dist\/.+\.js$/,
  /^hardening\/cloudpanel-mcp-gate\.sh$/,
  /^hardening\/cloudpanel-mcp-setup\.sh$/,
  /^inventory\/cloudpanel-mcp-inventory$/,
  /^docs\/[A-Za-z0-9._-]+\.md$/,
  /^docs\/adr\/[A-Za-z0-9._-]+\.md$/,
  /^(README|SECURITY|CHANGELOG|CONTRIBUTING|CODE_OF_CONDUCT)\.md$/,
  /^(LICENSE|NOTICE|package\.json)$/,
];
const bad = files.filter((f) => !allowed.some((re) => re.test(f)));
const required = ["dist/index.js", "hardening/cloudpanel-mcp-gate.sh", "hardening/cloudpanel-mcp-setup.sh", "inventory/cloudpanel-mcp-inventory", "LICENSE", "README.md", "package.json"];
const missing = required.filter((f) => !files.includes(f));
if (bad.length > 0 || missing.length > 0 || (process.platform !== "win32" && notExecutable.length > 0)) {
  process.stderr.write(`unexpected files: ${bad.join(", ") || "(none)"}\nmissing files: ${missing.join(", ") || "(none)"}\nnot executable: ${notExecutable.join(", ") || "(none)"}\n`);
  process.exit(1);
}
process.stdout.write(`pack ok: ${files.length} files\n`);
