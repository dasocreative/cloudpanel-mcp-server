import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { buildCatalog } from "../src/catalog/index.ts";
import { KNOWN_COMMANDS } from "../src/catalog/documented.ts";
import { describeTool, envelopeShape, inputSchemaOf } from "../src/catalog/define.ts";
import { isValidOption } from "../src/validate/option-types.ts";
import { ROOT, makeProfile } from "./helpers.ts";
import { DIR, SAMPLE_ARGS } from "./samples.ts";

const catalog = buildCatalog();
const profile = makeProfile({ siteUserAccess: { shop: { host: "shop-alias" } } });

describe("the catalogue", () => {
  it("has unique tool names that follow the clp_ convention", () => {
    const names = catalog.map((s) => s.name);
    assert.equal(new Set(names).size, names.length);
    for (const spec of catalog) {
      assert.match(spec.name, /^clp_[a-z0-9_]+$/);
      if (spec.command !== null) {
        assert.equal(spec.name, `clp_${spec.command.replaceAll(":", "_").replaceAll("-", "_")}`);
      }
    }
  });

  it("has a sample for every tool and no sample for a missing one", () => {
    assert.deepEqual(Object.keys(SAMPLE_ARGS).sort(), catalog.map((s) => s.name).sort());
  });

  it("accepts its sample arguments through the real schema, and rejects extra keys", () => {
    for (const spec of catalog) {
      const schema = inputSchemaOf(spec, ["test"], "test");
      const sample = SAMPLE_ARGS[spec.name] ?? {};
      assert.ok(schema.safeParse(sample).success, `${spec.name}: ${JSON.stringify(schema.safeParse(sample))}`);
      assert.ok(!schema.safeParse({ ...sample, extra: 1 }).success, `${spec.name} must be strict`);
      assert.ok(!schema.safeParse({ ...sample, profile: "other" }).success);
    }
  });

  it("builds plans whose options are declared, typed correctly and complete", () => {
    for (const spec of catalog) {
      if (spec.plan === undefined) continue;
      const args = SAMPLE_ARGS[spec.name] ?? {};
      const plan = spec.plan(args, profile);
      assert.equal(plan.command, spec.command, spec.name);
      const sent = new Set<string>();
      for (const o of plan.options) {
        const def = spec.options[o.name];
        assert.ok(def !== undefined, `${spec.name} sends undeclared option ${o.name}`);
        sent.add(o.name);
        if (o.generated !== undefined) {
          assert.equal(def.type, "password", `${spec.name}.${o.name}`);
        } else {
          assert.ok(isValidOption(def.type, o.value ?? "", profile), `${spec.name}.${o.name}=${o.value} is not a valid ${def.type}`);
        }
      }
      for (const [name, def] of Object.entries(spec.options)) {
        if (def.required) assert.ok(sent.has(name), `${spec.name} declares ${name} required but does not send it`);
      }
      for (const flag of plan.flags) assert.ok(spec.flags.includes(flag), `${spec.name} sends undeclared flag ${flag}`);
      assert.ok(plan.summary.length > 5);
      assert.ok(plan.undo.length > 3);
      if (spec.cls === "destructive" || spec.cls === "admin") {
        assert.ok(plan.confirm !== undefined && plan.confirm.target.length > 0, `${spec.name} needs a typed target`);
      }
      if (spec.cls !== "read") assert.ok(plan.effects.length > 0, `${spec.name} must say what it does`);
    }
  });

  it("classifies tools as the specification says and sets the Claude Code metadata only on destructive and admin", () => {
    const expect: Record<string, string> = {
      clp_site_delete: "destructive", clp_db_import: "destructive", clp_db_delete: "destructive", clp_vhost_template_delete: "destructive",
      clp_user_add: "admin", clp_user_delete: "admin", clp_user_reset_password: "admin", clp_user_disable_mfa: "admin",
      clp_cloudpanel_enable_basic_auth: "admin", clp_cloudpanel_disable_basic_auth: "admin", clp_cloudpanel_set_release_channel: "admin",
      clp_db_show_master_credentials: "admin",
      clp_site_add_php: "write", clp_lets_encrypt_install_certificate: "write", clp_db_export: "write",
      clp_user_list: "read", clp_vhost_templates_list: "read", clp_vhost_template_view: "read", clp_server_info: "read",
    };
    for (const spec of catalog) {
      const want = expect[spec.name];
      if (want !== undefined) assert.equal(spec.cls, want, spec.name);
      const d = describeTool(spec, ["test"], "test");
      assert.equal(d._meta?.["anthropic/requiresUserInteraction"] === true, spec.cls === "destructive" || spec.cls === "admin", spec.name);
      assert.equal(d.annotations["readOnlyHint"], spec.cls === "read", spec.name);
      assert.equal(d.annotations["openWorldHint"] === true || d.annotations["openWorldHint"] === false, true);
      if (spec.cls === "destructive") assert.equal(d.annotations["destructiveHint"], true, spec.name);
    }
  });

  it("has static descriptions that tell the model what to expect", () => {
    for (const spec of catalog) {
      assert.ok(spec.description.length > 60, spec.name);
      assert.match(spec.description, /Class (READ|WRITE|DESTRUCTIVE|ADMIN)/);
      assert.match(spec.description, /untrusted data/);
      if (spec.cls === "destructive" || spec.cls === "admin") assert.match(spec.description, /planToken/);
      if (spec.cls === "write") assert.match(spec.description, /dryRun/);
      if (Object.values(spec.options).some((o) => o.type === "password")) assert.match(spec.description, /Passwords are never parameters/);
    }
  });

  it("never takes a password, a confirm string or a raw command as a parameter", () => {
    for (const spec of catalog) {
      const keys = Object.keys(inputSchemaOf(spec, ["test"], "test").def !== undefined ? (describeTool(spec, ["test"], "test").inputSchema["properties"] as object) : {});
      for (const key of keys) {
        assert.ok(!/pass|confirm|command|shell|script|sudo/i.test(key), `${spec.name} has parameter ${key}`);
      }
    }
  });

  it("describes envelope fields only for changing tools", () => {
    assert.deepEqual(Object.keys(envelopeShape("read", ["a"], "a")), ["profile"]);
    assert.deepEqual(Object.keys(envelopeShape("write", ["a"], "a")), ["profile", "dryRun", "planToken"]);
  });

  it("keeps docs/COMMAND-REFERENCE.md and the catalogue in step", () => {
    const doc = readFileSync(join(ROOT, "docs", "COMMAND-REFERENCE.md"), "utf8");
    const rows = [...doc.matchAll(/^\| `([a-z:-]+)` \|[^|]*\|[^|]*\|[^|]*\|[^|]*\| (none|`clp_[a-z_]+`) \|$/gm)];
    const inDocs = new Map(rows.map((m) => [m[1] as string, m[2] as string]));
    const inCatalog = new Map(catalog.filter((s) => s.command !== null).map((s) => [s.command as string, `\`${s.name}\``]));
    for (const [command, tool] of inCatalog) assert.equal(inDocs.get(command), tool, `${command} in docs/COMMAND-REFERENCE.md`);
    for (const [command, tool] of inDocs) {
      if (tool !== "none") assert.ok(inCatalog.has(command), `${command} is documented with a tool but the catalogue lacks it`);
    }
    const known = new Set(KNOWN_COMMANDS.map((k) => k.command));
    for (const command of inDocs.keys()) assert.ok(known.has(command), `${command} is in the doc index but not in KNOWN_COMMANDS`);
    for (const command of known) assert.ok(inDocs.has(command), `${command} is in KNOWN_COMMANDS but not in the doc index`);
  });

  it("keeps the sample arguments inside the helper profile's directories", () => {
    assert.equal(DIR, makeProfile().fileDirs[0]);
  });
});
