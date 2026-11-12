import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { describe, it } from "node:test";
import { README_PATH, TOOLS_PATH, toolsDoc, withTables } from "../scripts/gen-docs.ts";
import { buildCatalog } from "../src/catalog/index.ts";
import { ENV_NAMES } from "../src/config/load.ts";
import { ROOT } from "./helpers.ts";

const catalog = buildCatalog();
const docs = (): string[] => {
  const files = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md"];
  for (const dir of ["docs", "docs/adr"]) for (const f of readdirSync(join(ROOT, dir))) if (f.endsWith(".md")) files.push(`${dir}/${f}`);
  return files;
};

describe("the documentation", () => {
  it("has a tool reference that is exactly what the catalogue generates", () => {
    assert.equal(readFileSync(TOOLS_PATH, "utf8"), toolsDoc());
    // the README keeps no generated tables of its own; if it ever has the markers again, they must be current
    const readme = readFileSync(README_PATH, "utf8");
    if (readme.includes("<!-- tools:start")) assert.equal(withTables(readme), readme);
    assert.match(readme, /docs\/TOOLS\.md/);
  });

  it("links only to files that exist", () => {
    const broken: string[] = [];
    for (const file of docs()) {
      const text = readFileSync(join(ROOT, file), "utf8").replace(/```[\s\S]*?```/g, "");
      for (const m of text.matchAll(/\[[^\]]*\]\(([^)\s]+)\)/g)) {
        const target = (m[1] as string).split("#")[0] as string;
        if (target === "" || /^(https?:|mailto:)/.test(target)) continue;
        const path = resolve(dirname(join(ROOT, file)), target);
        if (!existsSync(path)) broken.push(`${file} -> ${target}`);
      }
    }
    assert.deepEqual(broken, []);
  });

  it("mentions only tools that exist", () => {
    const known = new Set(catalog.map((s) => s.name));
    const unknown: string[] = [];
    for (const file of docs()) {
      const text = readFileSync(join(ROOT, file), "utf8");
      for (const m of text.matchAll(/\bclp_[a-z0-9_]+\b/g)) {
        const name = m[0];
        if (!known.has(name) && !name.endsWith("_") && !/^clp_(s|d|a)$/.test(name)) unknown.push(`${file}: ${name}`);
      }
    }
    assert.deepEqual([...new Set(unknown)], []);
  });

  it("documents exactly the environment variables the server accepts (docs/CONFIGURATION.md)", () => {
    const readme = readFileSync(join(ROOT, "docs", "CONFIGURATION.md"), "utf8");
    const mentioned = new Set([...readme.matchAll(/CLOUDPANEL_MCP_([A-Z_]+)/g)].map((m) => m[1] as string));
    const accepted = new Set<string>(ENV_NAMES);
    for (const name of mentioned) {
      // the table abbreviates a family as `_SSH_USER` after its first member; those are fine when a longer accepted name ends with them
      const known = accepted.has(name) || [...accepted].some((a) => a.endsWith(name.replace(/^_/, "")));
      assert.ok(known || name === "", `docs/CONFIGURATION.md mentions CLOUDPANEL_MCP_${name}, which the server does not accept`);
    }
    for (const name of accepted) assert.ok(readme.includes(name), `docs/CONFIGURATION.md does not document CLOUDPANEL_MCP_${name}`);
  });

  it("agrees with package.json on the Node version and does not publish tests or sources", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { engines: { node: string }; files: string[]; private?: boolean; scripts: Record<string, string> };
    assert.equal(pkg.engines.node, ">=22");
    assert.match(readFileSync(join(ROOT, "README.md"), "utf8"), /Node\.js 22 or newer/);
    for (const f of pkg.files) assert.ok(!/^(src|test|scripts)(\/|$)/.test(f), f);
    for (const name of ["preinstall", "install", "postinstall", "prepare"]) assert.ok(!(name in pkg.scripts), name);
  });

  it("does not claim a verification that has not happened", () => {
    const review = readFileSync(join(ROOT, "docs", "SECURITY-REVIEW.md"), "utf8");
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    if (/Status: \*\*not yet done/.test(review)) {
      assert.ok(!/review was done/i.test(readme));
    }
    assert.ok(relative(ROOT, README_PATH) === "README.md");
  });
});
