import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildCatalog } from "../src/catalog/index.ts";
import { FILE_KINDS, type FileKind } from "../src/validate/patterns.ts";
import { FakeIO, approve, bodyOf, makeHarness, makeProfile, noHuman, okResult } from "./helpers.ts";
import { DIR, SAMPLE_ARGS } from "./samples.ts";

const catalog = buildCatalog();
const profile = makeProfile();

/** What a protect list of each kind guards: an option of this type names such a target. */
const KIND_OF_TYPE: Record<string, string> = {
  domain: "domain",
  domainList: "domain",
  siteUser: "siteUser",
  userDbName: "database",
  panelUser: "panelUser",
};

/** Options that share a type with a protectable name but name something else. */
const NOT_A_PROTECTABLE_NAME = new Set(["clp_cloudpanel_enable_basic_auth.userName"]); // the HTTP basic-auth user, not a panel user

describe("the protect rule is uniform", () => {
  it("every changing clpctl tool that takes a protectable name checks it", () => {
    const missing: string[] = [];
    for (const spec of catalog) {
      if (spec.kind !== "clpctl" || spec.cls === "read") continue;
      for (const [option, def] of Object.entries(spec.options)) {
        if (NOT_A_PROTECTABLE_NAME.has(`${spec.name}.${option}`)) continue;
        const kind = KIND_OF_TYPE[def.type];
        if (kind !== undefined && spec.protectOptions[option] !== kind) missing.push(`${spec.name}.${option} (${def.type}) is not declared as a protected ${kind}`);
      }
    }
    assert.deepEqual(missing, []);
  });
  it("a plan names a protect check for exactly the targets its protect options name", () => {
    for (const spec of catalog) {
      if (spec.plan === undefined) continue;
      const plan = spec.plan(SAMPLE_ARGS[spec.name] ?? {}, profile);
      const expected = Object.entries(spec.protectOptions)
        .flatMap(([option, kind]) => String(plan.options.find((o) => o.name === option)?.value).split(",").map((v) => `${kind}:${v}`))
        .sort();
      const actual = plan.protect.filter((p) => spec.kind === "clpctl" || p.kind !== "siteUser").map((p) => `${p.kind}:${p.value}`).sort();
      assert.deepEqual(actual, expected, spec.name);
    }
  });
  it("a site-user tool checks the site user it logs in as", () => {
    for (const name of ["clp_system_permissions_reset", "clp_varnish_cache_purge"]) {
      const spec = catalog.find((s) => s.name === name);
      const plan = (spec?.plan as NonNullable<typeof spec>["plan"] & object)(SAMPLE_ARGS[name] ?? {}, profile);
      assert.deepEqual(plan.protect, [{ kind: "siteUser", value: "shop" }], name);
    }
  });
});

describe("protected targets are refused by the server for every tool that names them", () => {
  const harness = (protect: Partial<Record<"domains" | "siteUsers" | "databases" | "panelUsers", string[]>>) =>
    makeHarness({
      profile: {
        protect: { domains: [], siteUsers: [], databases: [], panelUsers: [], ...protect },
        siteUserAccess: { shop: { host: "shop-alias" } },
      },
    });
  const KINDS: Record<string, keyof NonNullable<Parameters<typeof harness>[0]>> = { domain: "domains", siteUser: "siteUsers", database: "databases", panelUser: "panelUsers" };

  for (const spec of catalog.filter((s) => s.plan !== undefined && s.cls !== "read" && Object.keys(s.protectOptions).length + (s.kind === "siteuser" ? 1 : 0) > 0)) {
    it(`${spec.name}`, async () => {
      const args = SAMPLE_ARGS[spec.name] ?? {};
      const plan = (spec.plan as NonNullable<typeof spec.plan>)(args, profile);
      assert.ok(plan.protect.length > 0, "the plan checks something");
      for (const check of plan.protect) {
        const list = KINDS[check.kind] as "domains";
        // domains are lower case in a configuration (it refuses anything else); the other names match without regard to case
        const h = harness({ [list]: [check.kind === "domain" ? check.value : check.value.toUpperCase()] });
        const io = new FakeIO(approve);
        const first = await h.call(spec.name, { ...args, dryRun: true }, io);
        const out = first.isError ? first : await h.call(spec.name, { ...args, planToken: String(bodyOf(first).planToken) }, io);
        assert.equal(out.isError, true, `${check.kind} ${check.value}: ${JSON.stringify(bodyOf(out))}`);
        assert.match(String(bodyOf(out).reason), /protected/, `${check.kind} ${check.value}`);
        assert.equal(io.asked.length, 0, "the human is not even asked");
        assert.equal(h.transport.calls.length, 0, "nothing was run, not even the probe");
      }
    });
  }

  it("a wildcard protects the apex and every name below it, www ignored, for the new tools too", async () => {
    const h = harness({ domains: ["*.prod.example.com"] });
    for (const domainName of ["prod.example.com", "www.prod.example.com", "a.b.prod.example.com"]) {
      const out = await h.call("clp_site_add_static", { domainName, siteUser: "abc" }, new FakeIO(approve));
      assert.equal(out.isError, true, domainName);
      assert.match(String(bodyOf(out).reason), /protected/);
    }
    const free = await h.call("clp_site_add_static", { domainName: "evilprod.example.com", siteUser: "abc" }, new FakeIO(approve));
    assert.equal(free.isError, false, JSON.stringify(bodyOf(free)));
  });

  it("every entry of a certificate's extra names is checked", async () => {
    const h = harness({ domains: ["panel.example.com"] });
    const out = await h.call("clp_lets_encrypt_install_certificate", { domainName: "a.example.com", subjectAlternativeName: ["b.example.com", "www.panel.example.com"] }, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.match(String(bodyOf(out).reason), /protected/);
  });

  it("the sites given to a new panel user are checked", async () => {
    const h = harness({ domains: ["shop.example.com"] });
    const args = { ...SAMPLE_ARGS["clp_user_add"], sites: ["other.example.com", "shop.example.com"] };
    const plan = await h.call("clp_user_add", { ...args, dryRun: true }, new FakeIO(approve));
    assert.equal(plan.isError, true);
    assert.match(String(bodyOf(plan).reason), /protected/);
  });
});

describe("deleting a panel user needs --force, and an unanswered question is a failure", () => {
  const seed = (h: ReturnType<typeof makeHarness>): void => {
    h.transport.state.users.push({ userName: "jane.doe", email: "j@example.com", firstName: "J", lastName: "D", role: "user", status: "1", sites: [] } as never);
  };
  it("sends --force and the user is gone", async () => {
    const h = makeHarness();
    seed(h);
    const out = await h.apply("clp_user_delete", { userName: "jane.doe" }, new FakeIO(approve));
    assert.equal(out.isError, false, JSON.stringify(bodyOf(out)));
    assert.match(String(bodyOf(out).command), /user:delete '--userName=jane\.doe' --force|user:delete --userName=jane\.doe --force|'--userName=jane\.doe' '--force'|--force/);
    assert.ok(!h.transport.state.users.some((u) => u.userName === "jane.doe"));
  });
  it("reports a failure when clpctl asks its question and does nothing, although it exits 0", async () => {
    const h = makeHarness();
    seed(h);
    h.transport.override = (request) =>
      request.argv.includes("user:delete") ? okResult({ exitCode: 0, stdout: "Confirm to delete the user: jane.doe (yes/no): " }) : undefined;
    const out = await h.apply("clp_user_delete", { userName: "jane.doe" }, new FakeIO(approve));
    assert.equal(out.isError, true);
    assert.equal(bodyOf(out).ok, false);
    assert.ok(h.transport.state.users.some((u) => u.userName === "jane.doe"), "the simulator confirms nothing was deleted");
  });
});

describe("database accounts the server never creates", () => {
  it("clp_db_add refuses root, mysql, clp and the other system accounts, in any case", async () => {
    const h = makeHarness();
    for (const user of ["root", "ROOT", "mysql", "MySQL", "clp", "cloudpanel", "debian_sys_maint", "mysql_sys", "sys"]) {
      const out = await h.call("clp_db_add", { domainName: "shop.example.com", databaseName: "shopdb", databaseUserName: user, dryRun: true }, new FakeIO(approve));
      assert.equal(out.isError, true, user);
      assert.match(String(bodyOf(out).reason), /invalid arguments/, user);
    }
    const ok = await h.call("clp_db_add", { domainName: "shop.example.com", databaseName: "shopdb", databaseUserName: "shop_user", dryRun: true }, new FakeIO(approve));
    assert.equal(ok.isError, false);
    assert.ok(h.transport.calls.every((c) => !c.argv.includes("db:add")), "a dry run runs no db:add");
  });
});

describe("databases the server never exports or imports into", () => {
  for (const name of ["mysql", "sys", "information_schema", "performance_schema", "clp", "cloudpanel", "CLP", "MySQL"]) {
    it(`${name}`, async () => {
      const h = makeHarness();
      for (const tool of ["clp_db_export", "clp_db_import", "clp_db_delete"]) {
        const args = tool === "clp_db_delete" ? { databaseName: name } : { databaseName: name, file: `${DIR}/dumps/x.sql` };
        const out = await h.call(tool, { ...args, dryRun: true }, new FakeIO(approve));
        assert.equal(out.isError, true, tool);
        assert.match(String(bodyOf(out).reason), /invalid arguments/, tool);
      }
      assert.equal(h.transport.calls.length, 0);
    });
  }
});

describe("files: a subdirectory and extensions per kind", () => {
  const cases: [tool: string, field: string, kind: FileKind, extra: Record<string, unknown>, ok: string, bad: string[]][] = [
    ["clp_db_export", "file", "dump", { databaseName: "shopdb" }, `${DIR}/dumps/a.sql`, [`${DIR}/a.sql`, `${DIR}/certs/a.sql`, `${DIR}/templates/a.sql`, `${DIR}/dumps/a.tpl`, `${DIR}/dumps/a.pem`, `${DIR}/dumps/a`, `${DIR}-x/dumps/a.sql`, "/etc/cron.d/x.sql", `${DIR}/dumps/../a.sql`]],
    ["clp_db_import", "file", "dump", { databaseName: "shopdb" }, `${DIR}/dumps/a.sql.gz`, [`${DIR}/a.sql`, `${DIR}/certs/a.sql`, `${DIR}/templates/a.sql`, `${DIR}/dumps/a.conf`]],
    ["clp_vhost_template_add", "file", "template", { name: "My" }, `${DIR}/templates/a.tpl`, [`${DIR}/a.tpl`, `${DIR}/dumps/a.tpl`, `${DIR}/dumps/a.sql`, `${DIR}/templates/a.sql`, `${DIR}/certs/a.conf`, `${DIR}/templates/a`]],
    ["clp_site_install_certificate", "certificate", "cert", { domainName: "a.example.com", privateKey: `${DIR}/certs/k.key` }, `${DIR}/certs/c.pem`, [`${DIR}/c.pem`, `${DIR}/dumps/c.pem`, `${DIR}/templates/c.pem`, `${DIR}/certs/c.sql`, `${DIR}/certs/c.tpl`]],
    ["clp_site_install_certificate", "privateKey", "cert", { domainName: "a.example.com", certificate: `${DIR}/certs/c.crt` }, `${DIR}/certs/k.key`, [`${DIR}/k.key`, `${DIR}/dumps/k.key`, `${DIR}/certs/k.sql`]],
    ["clp_site_install_certificate", "certificateChain", "cert", { domainName: "a.example.com", privateKey: `${DIR}/certs/k.key`, certificate: `${DIR}/certs/c.crt` }, `${DIR}/certs/ch.ca-bundle`, [`${DIR}/ch.ca-bundle`, `${DIR}/dumps/ch.ca-bundle`]],
  ];
  for (const [tool, field, kind, extra, ok, bad] of cases) {
    it(`${tool}.${field} takes a ${kind} file in its own place only`, async () => {
      const h = makeHarness();
      const accepted = await h.call(tool, { ...extra, [field]: ok, dryRun: true }, new FakeIO(approve));
      assert.equal(accepted.isError, false, `${ok}: ${JSON.stringify(bodyOf(accepted))}`);
      for (const file of bad) {
        const out = await h.call(tool, { ...extra, [field]: file, dryRun: true }, new FakeIO(approve));
        assert.equal(out.isError, true, file);
        assert.match(String(bodyOf(out).reason), /invalid arguments/, file);
        assert.ok(!String(bodyOf(out).reason).includes(file) || file.length < 6, "the path is not echoed");
      }
    });
  }
  it("covers every kind of file", () => {
    assert.deepEqual([...new Set(cases.map((c) => c[2]))].sort(), [...FILE_KINDS].sort());
  });
  it("the chain from the review is cut: a dump cannot become a template, a certificate or a second dump elsewhere", async () => {
    const h = makeHarness();
    const dump = `${DIR}/dumps/stolen.sql`;
    assert.equal((await h.call("clp_db_export", { databaseName: "shopdb", file: dump, dryRun: true }, new FakeIO(approve))).isError, false);
    assert.equal((await h.call("clp_vhost_template_add", { name: "Evil", file: dump, dryRun: true }, new FakeIO(approve))).isError, true);
    assert.equal((await h.call("clp_site_install_certificate", { domainName: "a.example.com", privateKey: dump, certificate: dump, dryRun: true }, new FakeIO(approve))).isError, true);
    assert.equal((await h.call("clp_db_export", { databaseName: "shopdb", file: `${DIR}/templates/evil.tpl`, dryRun: true }, new FakeIO(approve))).isError, true);
    assert.equal((await h.call("clp_db_export", { databaseName: "shopdb", file: `${DIR}/certs/evil.pem`, dryRun: true }, new FakeIO(approve))).isError, true);
  });
});

describe("application ports", () => {
  const node = (appPort: number): Record<string, unknown> => ({ domainName: "node.example.com", nodejsVersion: "22", appPort, siteUser: "nodeapp" });

  it("only the profile's ports are accepted, by default the usual web-app ports", async () => {
    const h = makeHarness();
    for (const port of [1337, 2368, 3000, 4999, 5000, 5173, 8000, 8080, 8199]) {
      assert.equal((await h.call("clp_site_add_nodejs", { ...node(port), dryRun: true }, new FakeIO(approve))).isError, false, String(port));
    }
    for (const port of [1024, 5001, 8201, 9000, 39400, 65535]) {
      const out = await h.call("clp_site_add_nodejs", { ...node(port), dryRun: true }, new FakeIO(approve));
      assert.equal(out.isError, true, String(port));
      assert.match(String(bodyOf(out).reason), /ports this profile allows/, String(port));
    }
    for (const port of [3306, 5432, 6379, 8443, 9200, 22, 80, 3389, 4369, 4505, 4646, 8001, 8086, 8200, 8500, 9090, 9100, 10255]) {
      assert.equal((await h.call("clp_site_add_nodejs", { ...node(port), dryRun: true }, new FakeIO(approve))).isError, true, String(port));
    }
  });
  it("a profile can widen or narrow the list; the denied ports stay out", async () => {
    const wide = makeHarness({ profile: { appPorts: [{ from: 1024, to: 65535 }] } });
    assert.equal((await wide.call("clp_site_add_python", { domainName: "py.example.com", pythonVersion: "3.12", appPort: 9000, siteUser: "pyapp", dryRun: true }, new FakeIO(approve))).isError, false);
    assert.equal((await wide.call("clp_site_add_nodejs", { ...node(3306), dryRun: true }, new FakeIO(approve))).isError, true);
    const narrow = makeHarness({ profile: { appPorts: [{ from: 39400, to: 39409 }] } });
    assert.equal((await narrow.call("clp_site_add_nodejs", { ...node(39405), dryRun: true }, new FakeIO(approve))).isError, false);
    assert.equal((await narrow.call("clp_site_add_nodejs", { ...node(3000), dryRun: true }, new FakeIO(approve))).isError, true);
  });
  it("a reverse-proxy upstream follows the same list, besides 80 and 443", async () => {
    const h = makeHarness();
    const proxy = (reverseProxyUrl: string): Record<string, unknown> => ({ domainName: "proxy.example.com", reverseProxyUrl, siteUser: "proxysite", dryRun: true });
    for (const url of ["http://127.0.0.1:8000", "http://127.0.0.1", "http://localhost:443", "http://127.0.0.1:3000/app"]) {
      assert.equal((await h.call("clp_site_add_reverse_proxy", proxy(url), new FakeIO(approve))).isError, false, url);
    }
    for (const url of ["http://127.0.0.1:9000", "http://127.0.0.1:22", "http://127.0.0.1:3306", "http://127.0.0.1:8443", "http://127.0.0.1:6379", "http://10.0.0.1:8000"]) {
      assert.equal((await h.call("clp_site_add_reverse_proxy", proxy(url), new FakeIO(approve))).isError, true, url);
    }
  });
});

describe("clp_server_info", () => {
  it("shows where each kind of file goes, the ports and warnings", async () => {
    const h = makeHarness({ profile: { protect: { domains: [], siteUsers: ["shop"], databases: ["maindb"], panelUsers: [] } } });
    const out = await h.call("clp_server_info", {}, noHuman);
    const info = bodyOf(out).profiles[0];
    assert.deepEqual(info.fileLocations.dumps.directories, [`${DIR}/dumps`]);
    assert.deepEqual(info.fileLocations.certs.directories, [`${DIR}/certs`]);
    assert.deepEqual(info.fileLocations.templates.directories, [`${DIR}/templates`]);
    assert.match(info.fileLocations.dumps.extensions, /\.sql/);
    assert.equal(info.appPorts, "1337, 2368, 3000-4999, 5000, 5173, 8000-8199");
    assert.ok(info.warnings.some((w: string) => /site user and the databases/.test(w)), JSON.stringify(info.warnings));
    assert.ok(info.warnings.some((w: string) => /no domain is protected/.test(w)));
  });
  it("warns about write tools that rely on the client, and says nothing when there is nothing to say", async () => {
    const client = makeHarness({ profile: { approvalWrite: "client", allow: new Set(["write"]) } });
    const w = bodyOf(await client.call("clp_server_info", {}, noHuman)).profiles[0].warnings;
    assert.equal(w.length, 1);
    assert.match(w[0], /relies? on the client|rely on the client/);
    const quiet = makeHarness({ profile: { allow: new Set(["write"]) } });
    assert.deepEqual(bodyOf(await quiet.call("clp_server_info", {}, noHuman)).profiles[0].warnings, []);
    const guarded = makeHarness({ profile: { protect: { domains: ["panel.example.com"], siteUsers: [], databases: [], panelUsers: [] } } });
    assert.deepEqual(bodyOf(await guarded.call("clp_server_info", {}, noHuman)).profiles[0].warnings, []);
  });
});
