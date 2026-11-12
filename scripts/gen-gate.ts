/**
 * Generates hardening/cloudpanel-mcp-gate.sh from the tool catalogue and the value patterns.
 *
 *   node scripts/gen-gate.ts            write the file
 *   node scripts/gen-gate.ts --check    exit 1 if the committed file differs (used by the tests and CI)
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildCatalog } from "../src/catalog/index.ts";
import type { ToolSpec } from "../src/catalog/define.ts";
import {
  DEFAULT_APP_PORTS,
  DENIED_APP_PORTS,
  FILE_EXT_SOURCES,
  FILE_KINDS,
  FILE_SUBDIR,
  FORBIDDEN_DIR_ROOTS,
  RESERVED_DATABASES,
  RESERVED_DB_USERS,
  RESERVED_SITE_USERS,
  SHARED_DIR_ROOTS,
  SOURCES,
  portRangeText,
  type PatternName,
} from "../src/validate/patterns.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const TEMPLATE_PATH = join(ROOT, "hardening", "gate.template.sh");
export const OUTPUT_PATH = join(ROOT, "hardening", "cloudpanel-mcp-gate.sh");

/** Types the template implements by hand; every other pattern name gets a plain regex case. */
const SPECIAL_TYPES = new Set(["domain", "siteUser", "dbUser", "email", "generatedPassword", "serverPath", "proxyUrl"]);

function bashSingleQuote(text: string): string {
  if (text.includes("'")) throw new Error(`cannot embed a single quote in a bash literal: ${text}`);
  return `'${text}'`;
}

function commandLine(spec: ToolSpec): string {
  const required = Object.entries(spec.options).filter(([, o]) => o.required).map(([n, o]) => `${n}:${o.type}`);
  const optional = Object.entries(spec.options).filter(([, o]) => !o.required).map(([n, o]) => `${n}:${o.type}`);
  const flags = spec.flags.map((f) => f.replace(/^--/, ""));
  const protect = Object.entries(spec.protectOptions).map(([n, k]) => `${n}:${k}`);
  const scope = spec.kind === "siteuser" ? "siteuser" : "root";
  const parts = [`CLASS=${spec.cls}`, `CMD_SCOPE=${scope}`];
  if (required.length > 0) parts.push(`REQ=${bashSingleQuote(required.join(" "))}`);
  if (optional.length > 0) parts.push(`OPT=${bashSingleQuote(optional.join(" "))}`);
  if (flags.length > 0) parts.push(`FLG=${bashSingleQuote(flags.join(" "))}`);
  if (protect.length > 0) parts.push(`PROT=${bashSingleQuote(protect.join(" "))}`);
  return `    ${spec.command}) ${parts.join("; ")} ;;`;
}

export function generateGate(): string {
  const specs = buildCatalog().filter((s) => (s.kind === "clpctl" || s.kind === "siteuser") && s.command !== null);
  const patterns = (Object.entries(SOURCES) as [PatternName, string][])
    .map(([name, source]) => `RE_${name}=${bashSingleQuote(source)}`)
    .join("\n");
  const patternCases = (Object.keys(SOURCES) as PatternName[])
    .filter((name) => !SPECIAL_TYPES.has(name))
    .map((name) => `    ${name}) [[ $value =~ $RE_${name} ]] ;;`)
    .join("\n");
  const list = (items: readonly (string | number)[]): string => items.join(" ");
  const generated = [
    "# ------------------------------------------------------------------------------------------",
    "# Generated from src/validate/patterns.ts and the catalogue. Do not edit by hand.",
    "# ------------------------------------------------------------------------------------------",
    patterns,
    `RESERVED_SITE_USERS=(${list(RESERVED_SITE_USERS)})`,
    `RESERVED_DATABASES=(${list(RESERVED_DATABASES)})`,
    `RESERVED_DB_USERS=(${list(RESERVED_DB_USERS)})`,
    `DENIED_PORTS=(${list(DENIED_APP_PORTS)})`,
    `FORBIDDEN_DIR_ROOTS=(${list(FORBIDDEN_DIR_ROOTS)})`,
    `SHARED_DIR_ROOTS=(${list(SHARED_DIR_ROOTS)})`,
    // each kind of file: its subdirectory and its extensions
    ...FILE_KINDS.flatMap((kind) => [`SUBDIR_${kind}=${FILE_SUBDIR[kind]}`, `RE_EXT_${kind}=${bashSingleQuote(FILE_EXT_SOURCES[kind])}`]),
    "",
    "# spec_lookup <command>: sets CLASS, CMD_SCOPE, REQ (required name:type), OPT (optional name:type),",
    "# FLG (flags) and PROT (options that name a protected target, name:kind).",
    "spec_lookup() {",
    "  CLASS=write",
    "  CMD_SCOPE=root",
    "  REQ=''",
    "  OPT=''",
    "  FLG=''",
    "  PROT=''",
    "  case $1 in",
    ...specs.map(commandLine),
    "    *) return 1 ;;",
    "  esac",
    "  return 0",
    "}",
  ].join("\n");
  const template = readFileSync(TEMPLATE_PATH, "utf8");
  if (!template.includes("@@GENERATED@@") || !template.includes("@@PATTERN_CASES@@")) throw new Error("the template lost a placeholder");
  if (!template.includes("@@DEFAULT_APP_PORTS@@")) throw new Error("the template lost a placeholder");
  return template
    .replace("@@GENERATED@@", () => generated)
    .replace("@@PATTERN_CASES@@", () => patternCases)
    .replace("@@DEFAULT_APP_PORTS@@", () => DEFAULT_APP_PORTS.map(portRangeText).join(" "));
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = generateGate();
  if (process.argv.includes("--check")) {
    let current = "";
    try {
      current = readFileSync(OUTPUT_PATH, "utf8");
    } catch {
      // missing
    }
    if (current !== text) {
      process.stderr.write("hardening/cloudpanel-mcp-gate.sh is out of date: run npm run gen:gate\n");
      process.exit(1);
    }
    process.stdout.write("hardening/cloudpanel-mcp-gate.sh is up to date\n");
  } else {
    writeFileSync(OUTPUT_PATH, text, { mode: 0o755 });
    process.stdout.write(`wrote ${OUTPUT_PATH}\n`);
  }
}
