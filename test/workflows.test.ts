import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { IS_WINDOWS, ROOT, shortTmp, writeExecutable } from "./helpers.ts";

const DIR = join(ROOT, ".github", "workflows");
const files = readdirSync(DIR).filter((f) => f.endsWith(".yml"));
const read = (name: string): string => readFileSync(join(DIR, name), "utf8");

/** The text of one job of a workflow: from "  <name>:" to the next job at the same indentation. */
function job(text: string, name: string): string {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => l === `  ${name}:`);
  assert.ok(start >= 0, `job ${name} not found`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[i] as string)) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

describe("the workflows", () => {
  it("exist", () => {
    assert.deepEqual(files.sort(), ["ci.yml", "codeql.yml", "dependency-review.yml", "release.yml"]);
  });

  it("use only actions pinned to a full commit, with the version in a comment", () => {
    for (const file of files) {
      for (const m of read(file).matchAll(/^\s*-?\s*uses:\s*(\S+)(.*)$/gm)) {
        assert.match(m[1] as string, /^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/, `${file}: ${m[1]}`);
        assert.match(m[2] as string, /#\s*v\d+\.\d+\.\d+/, `${file}: ${m[1]} lacks its version comment`);
      }
    }
  });

  it("never run on pull_request_target or with the workflow_run trigger, and pass no secret to a pull request", () => {
    for (const file of files) {
      const text = read(file);
      assert.ok(!/pull_request_target|workflow_run/.test(text), file);
      if (file !== "release.yml") assert.ok(!/secrets\./.test(text.replace(/GITHUB_TOKEN/g, "")), `${file} uses a secret`);
    }
  });

  it("start from read-only permissions", () => {
    for (const file of files) {
      const text = read(file);
      assert.match(text, /^permissions:\s*(\{\}|\n {2}[a-z-]+: (read|none))/m, file);
      assert.ok(!/permissions:\s*write-all/.test(text), file);
    }
  });

  it("keep the checkout from leaving credentials behind", () => {
    for (const file of files) {
      for (const m of read(file).matchAll(/uses: actions\/checkout@[^\n]*\n((?: {8,}[^\n]*\n)*)/g)) {
        assert.match(m[1] as string, /persist-credentials: false/, file);
      }
    }
  });
});

describe("the release workflow (prepared, inactive)", () => {
  const text = read("release.yml");
  const verify = job(text, "verify");
  const build = job(text, "build");
  const publish = job(text, "publish");

  it("does nothing unless the maintainer switched releases on, and only from the default branch", () => {
    assert.match(verify, /if: .*vars\.RELEASE_ENABLED == 'true'/);
    assert.match(verify, /github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/);
    assert.match(build, /needs: verify/);
    assert.match(publish, /needs: build/);
    assert.ok(!/^\s+if:/m.test(build) && !/^\s+if:/m.test(publish), "the later jobs depend on the first one, so they are skipped with it");
  });

  it("starts with no permission at all", () => {
    assert.match(text, /^permissions: \{\}$/m);
  });

  it("never lets a job that runs repository code hold the right to publish", () => {
    for (const [name, body] of [["verify", verify], ["build", build]] as const) {
      assert.ok(!/id-token/.test(body), `${name}: no id-token`);
      assert.ok(!/NPM_TOKEN|NODE_AUTH_TOKEN|npm publish|environment:/.test(body), `${name}: no token, no publish, no environment`);
      assert.match(body, /contents: read/);
    }
  });

  it("makes the publishing job run no repository code", () => {
    assert.match(publish, /id-token: write/);
    assert.match(publish, /environment: npm-publish/);
    assert.ok(!/actions\/checkout/.test(publish), "no checkout");
    assert.ok(!/npm (ci|install|test|run)\b/.test(publish), "no npm script of the repository");
    assert.ok(!/node scripts\//.test(publish), "no script of the repository");
    assert.match(publish, /npm publish \.\/cloudpanel-mcp-server-\*\.tgz --provenance --access public --ignore-scripts/);
  });

  it("runs the dev dependencies and the tests in the verifying job only; the building job runs just the compiler", () => {
    assert.match(verify, /npm ci\n/);
    assert.match(verify, /npm test/);
    assert.match(build, /npm ci --ignore-scripts/);
    assert.ok(!/npm test|check-hygiene|node --test/.test(build), "no test code in the building job");
    assert.match(build, /npm run build/);
  });

  it("restores no cache in any job", () => {
    assert.ok(!/^\s+cache:\s/m.test(text), "no cache: key in a setup step");
    assert.ok(!/actions\/cache/.test(text));
  });

  it("runs every check in the verifying job", () => {
    const order = ["npm ci", "npm test", "check-hygiene.mjs --history-content", "gen-gate.ts --check", "gen-docs.ts --check", "npm audit", "npm run check:pack"];
    let at = -1;
    for (const needle of order) {
      const next = verify.indexOf(needle, at + 1);
      assert.ok(next > at, `${needle} comes after the previous step`);
      at = next;
    }
  });

  it("packs once, in one step with the checksum, and hands the checksum to the publishing job", () => {
    assert.equal((build.match(/npm pack/g) ?? []).length, 1);
    assert.match(build, /npm pack --ignore-scripts[\s\S]*sha256sum[\s\S]*GITHUB_OUTPUT/);
    assert.match(build, /outputs:\n\s+sha256: \$\{\{ steps\.pack\.outputs\.sha256 \}\}/);
    assert.match(build, /upload-artifact/);
    assert.match(publish, /EXPECTED_SHA256: \$\{\{ needs\.build\.outputs\.sha256 \}\}/);
  });

  it("checks the tarball it publishes: the checksum, one file, the name, public, the version, no install-time script, the dependencies, the file list", () => {
    for (const needle of ["exactly one tarball", "not the one the build job packed", "unexpected package name", "marked private", "version mismatch", "install-time script", "unexpected dependencies", "not pinned to an exact version", "unexpected bin", "unexpected files in the tarball"]) {
      assert.ok(publish.includes(needle), needle);
    }
  });

  it("allows exactly the files that scripts/check-pack.mjs allows", () => {
    const regexes = (source: string): string[] =>
      [...source.slice(source.indexOf("const allowed = [")).split("];")[0]!.matchAll(/^\s*(\/.+\/),?$/gm)].map((m) => (m[1] as string).replaceAll("\\$", "$"));
    const fromScript = regexes(readFileSync(join(ROOT, "scripts", "check-pack.mjs"), "utf8"));
    const fromWorkflow = regexes(publish);
    assert.ok(fromScript.length >= 6);
    assert.deepEqual(fromWorkflow, fromScript);
  });

  it("expects the dependencies the package really has", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { dependencies: Record<string, string>; bin: Record<string, string> };
    assert.deepEqual(Object.keys(pkg.dependencies).sort(), ["@modelcontextprotocol/server", "zod"]);
    assert.ok(publish.includes("'@modelcontextprotocol/server,zod'"));
    assert.ok(Object.values(pkg.dependencies).every((v) => /^\d+\.\d+\.\d+$/.test(v)));
    assert.deepEqual(pkg.bin, { "cloudpanel-mcp-server": "dist/index.js" });
  });
});

describe("continuous integration", () => {
  it("scans the whole history, contents included, and the generated files", () => {
    const ci = read("ci.yml");
    assert.match(ci, /fetch-depth: 0/);
    assert.match(ci, /check-hygiene\.mjs --history-content/);
    assert.match(ci, /gen-gate\.ts --check/);
    assert.match(ci, /gen-docs\.ts --check/);
  });
  it("tests on Linux, macOS and Windows with Node 22 and 24", () => {
    const ci = read("ci.yml");
    for (const needle of ["ubuntu-latest", "macos-latest", "windows-latest", "node: [22, 24]"]) assert.ok(ci.includes(needle), needle);
  });
});

describe("the publishing job's check, run for real on a real tarball", { skip: IS_WINDOWS }, () => {
  const version = (JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string }).version;

  /** The shell of the step, as the runner would run it. */
  function stepScript(): string {
    const text = read("release.yml");
    const start = text.indexOf("      - name: The tarball is the one that was built");
    const runAt = text.indexOf("        run: |\n", start);
    const end = text.indexOf("\n      - name:", runAt);
    return text
      .slice(runAt + "        run: |\n".length, end)
      .split("\n")
      .map((line) => line.slice(10))
      .join("\n");
  }

  /** `sha256sum` exists on the runner, not on every developer machine. */
  function shim(): string {
    const bin = shortTmp("clpb-");
    writeExecutable(
      bin,
      "sha256sum",
      `#!${process.execPath}\nconst { createHash } = require("node:crypto");\nconst { readFileSync } = require("node:fs");\nfor (const f of process.argv.slice(2)) console.log(createHash("sha256").update(readFileSync(f)).digest("hex") + "  " + f);\n`,
    );
    return bin;
  }

  /** The real package, packed now, made public and given the requested version; `change` may tamper with the unpacked copy. */
  function tarball(change: (pkgDir: string, manifest: Record<string, any>) => void = () => undefined): { dir: string; sha: string } {
    const work = shortTmp("clpr-");
    const packed = spawnSync("npm", ["pack", "--ignore-scripts", "--pack-destination", work], { cwd: ROOT, encoding: "utf8" });
    assert.equal(packed.status, 0, packed.stderr);
    const name = readdirSync(work).find((f) => f.endsWith(".tgz")) as string;
    const unpacked = join(work, "unpacked");
    mkdirSync(unpacked);
    assert.equal(spawnSync("tar", ["-xzf", join(work, name), "-C", unpacked]).status, 0);
    const manifestPath = join(unpacked, "package", "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, any>;
    delete manifest["private"];
    change(join(unpacked, "package"), manifest);
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    const out = shortTmp("clpo-");
    assert.equal(spawnSync("tar", ["-czf", join(out, name), "-C", unpacked, "package"]).status, 0);
    return { dir: out, sha: createHash("sha256").update(readFileSync(join(out, name))).digest("hex") };
  }

  function check(rig: { dir: string; sha: string }, env: Record<string, string> = {}): { status: number | null; output: string } {
    const script = join(rig.dir, "step.sh");
    writeFileSync(script, stepScript());
    const r = spawnSync("bash", ["-eu", script], {
      cwd: rig.dir,
      encoding: "utf8",
      env: { PATH: `${shim()}:${process.env["PATH"] ?? "/usr/bin:/bin"}`, REQUESTED: version, EXPECTED_SHA256: rig.sha, ...env },
    });
    return { status: r.status, output: `${r.stdout}${r.stderr}` };
  }

  it("accepts the real package, made public", () => {
    const r = check(tarball());
    assert.equal(r.status, 0, r.output);
  });

  const refused: [string, (pkgDir: string, manifest: Record<string, any>) => void, RegExp][] = [
    ["a tarball that is still private", (_d, m) => { m["private"] = true; }, /marked private/],
    ["another package name", (_d, m) => { m["name"] = "something-else"; }, /unexpected package name/],
    ["a postinstall script", (_d, m) => { m["scripts"] = { ...m["scripts"], postinstall: "node x.js" }; }, /install-time script: postinstall/],
    ["a preinstall script", (_d, m) => { m["scripts"] = { ...m["scripts"], preinstall: "node x.js" }; }, /install-time script: preinstall/],
    ["a prepare script", (_d, m) => { m["scripts"] = { ...m["scripts"], prepare: "node x.js" }; }, /install-time script: prepare/],
    ["a prepack script", (_d, m) => { m["scripts"] = { ...m["scripts"], prepack: "node x.js" }; }, /install-time script: prepack/],
    ["an extra dependency", (_d, m) => { m["dependencies"] = { ...m["dependencies"], "left-pad": "1.3.0" }; }, /unexpected dependencies/],
    ["a dependency that is a range", (_d, m) => { m["dependencies"] = { ...m["dependencies"], zod: "^4.0.0" }; }, /not pinned to an exact version/],
    ["an optional dependency", (_d, m) => { m["optionalDependencies"] = { x: "1.0.0" }; }, /optional, peer or bundled/],
    ["another bin", (_d, m) => { m["bin"] = { "cloudpanel-mcp-server": "dist/evil.js" }; }, /unexpected bin/],
    ["a file that is not meant to be published", (dir) => { writeFileSync(join(dir, "evil.js"), "x"); }, /unexpected files in the tarball: evil\.js/],
    ["a dot file", (dir) => { writeFileSync(join(dir, ".npmrc"), "x"); }, /unexpected files in the tarball: \.npmrc/],
    ["a script in a directory that is not published", (dir) => { mkdirSync(join(dir, "scripts")); writeFileSync(join(dir, "scripts", "x.sh"), "x"); }, /unexpected files in the tarball: scripts\/x\.sh/],
  ];
  for (const [name, change, expected] of refused) {
    it(`refuses ${name}`, () => {
      const r = check(tarball(change));
      assert.notEqual(r.status, 0, r.output);
      assert.match(r.output, expected);
    });
  }

  it("refuses a tarball whose checksum is not the one the building job recorded", () => {
    const rig = tarball();
    const r = check(rig, { EXPECTED_SHA256: "0".repeat(64) });
    assert.notEqual(r.status, 0);
    assert.match(r.output, /not the one the build job packed/);
  });
  it("refuses another version than the one asked for", () => {
    const r = check(tarball(), { REQUESTED: "9.9.9" });
    assert.notEqual(r.status, 0);
    assert.match(r.output, /version mismatch/);
  });
  it("refuses two tarballs", () => {
    const rig = tarball();
    const name = readdirSync(rig.dir).find((f) => f.endsWith(".tgz")) as string;
    writeFileSync(join(rig.dir, "cloudpanel-mcp-server-0.0.1.tgz"), readFileSync(join(rig.dir, name)));
    const r = check(rig);
    assert.notEqual(r.status, 0);
    assert.match(r.output, /exactly one tarball/);
  });
});
