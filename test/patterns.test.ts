import assert from "node:assert/strict";
import { describe, it } from "node:test";
import fc from "fast-check";
import {
  DEFAULT_APP_PORTS,
  DENIED_APP_PORTS,
  FILE_EXT_TEXT,
  FILE_KINDS,
  FILE_SUBDIR,
  RE,
  RESERVED_DATABASES,
  RESERVED_DB_USERS,
  SOURCES,
  isAllowedProxyUrl,
  isAppPort,
  isCleanPath,
  isDomain,
  isKindPath,
  isPortAllowedAtAll,
  isUnderDirs,
  kindDirs,
  kindPathProblem,
  parseProxyUrl,
  parsePurge,
  portRangeText,
  portRangesText,
  proxyUrlProblem,
  type PatternName,
  type PortRange,
} from "../src/validate/patterns.ts";
import {
  appPortSchema,
  dbNameSchema,
  dbUserSchema,
  domainSchema,
  fileModeSchema,
  panelUserSchema,
  purgeSchema,
  relativePathSchema,
  siteUserSchema,
  userDbNameSchema,
} from "../src/validate/schemas.ts";
import { isValidOption } from "../src/validate/option-types.ts";
import { FORBIDDEN_IN_VALUES, HOSTILE } from "./corpus.ts";
import { makeProfile } from "./helpers.ts";

const CTX = { fileDirs: makeProfile().fileDirs, proxyHosts: makeProfile().proxyHosts, appPorts: makeProfile().appPorts };

const CASES: Record<PatternName, { valid: string[]; invalid: string[] }> = {
  domain: {
    valid: ["example.com", "www.example.com", "a-b.example.co.uk", "xn--bcher-kva.example", "1.example.com", "a.b.c.d.example.com", "shop.example.io"],
    invalid: ["example", "Example.com", "a_b.example.com", "example.c", "a.example.com.", "-a.example.com", "a.-b.example.com", "a..example.com", "a.example.com/", "a.example.com:80", "a.example.com ", "ａ.example.com", "a.example.c", "*.example.com", ""],
  },
  siteUser: { valid: ["shop", "john-doe", "a1_b", "x"], invalid: ["Shop", "1shop", "-shop", "_shop", "a b", "a.b", "a".repeat(33), "", "shop\n"] },
  dbName: { valid: ["my-database", "shopdb", "a", "A1-b2", "9lives"], invalid: ["my_database", "-db", "db name", "d.b", "a".repeat(65), "", "db\n", "db;"] },
  dbUser: { valid: ["john", "shop_user", "A1_", "x"], invalid: ["john-doe", "a b", "a.b", "a".repeat(65), "", "x\n", "-x"] },
  templateName: { valid: ["Generic", "My Application", "PrestaShop 1.7", "Laravel 13", "WordPress", "Contao 4", "WHMCS", "a_b-c", "x.", "1"], invalid: [" Generic", "Generic ", "-Generic", ".x", "_x", ".", "a'b", "a\"b", "a/b", "a\nb", "", "a".repeat(65), "x;y"] },
  panelUser: { valid: ["john.doe", "admin", "a-b_c.d", "A1"], invalid: ["-john", ".john", "john doe", "john@x", "", "a".repeat(65), "j\n"] },
  email: { valid: ["john.doe@domain.com", "a+b@example.org", "x@a.b.example.com", "A1@Example.COM"], invalid: ["john@", "@x.com", "a b@x.com", "a@x", "a@x.c", "a@@x.com", "<a>@x.com", "a@x.com\n", "a@-x.com", ".a@x.com", "a@x.com;id"] },
  person: { valid: ["John", "Mary Ann", "Jean-Luc", "O"], invalid: ["", "John1", "John ", " John", "-John", "O'Brien", "José", "John\n", "a".repeat(65)] },
  timezone: { valid: ["UTC", "Europe/Berlin", "Africa/Casablanca", "America/Argentina/Buenos_Aires", "Etc/GMT+1"], invalid: ["", "/UTC", "UTC/", "a/b/c/d", "UTC ", "Europe//Berlin", "1UTC", "UTC;id", "Europe/Be rlin"] },
  generatedPassword: { valid: ["A".repeat(32), "abcdefghijklmnopqrstuvwxyz012345"], invalid: ["A".repeat(31), "A".repeat(33), "A".repeat(31) + "!", "A".repeat(31) + "'", ""] },
  serverPath: { valid: ["/var/lib/x/a.sql", "/a", "/a/b-c_d.e"], invalid: ["a/b", "", "/", "/a b", "/a'b", "/a$b", "/a;b", "/a\n", "/" + "a".repeat(256)] },
  proxyUrl: {
    valid: ["http://127.0.0.1:8000", "http://localhost", "https://localhost:8443/app", "http://[::1]:3000", "http://127.0.0.1/", "http://127.0.0.1:8000/a/b.c"],
    invalid: ["ftp://127.0.0.1", "http://", "http://127.0.0.1:0", "http://127.0.0.1:08", "http://user@127.0.0.1", "http://127.0.0.1 ", "HTTP://127.0.0.1", "http://127.0.0.1/a b", "http://127.0.0.1/a?x=1", "http://127.0.0.1#x", "http://127.0.0.1\n"],
  },
  phpVersion: { valid: ["8.4", "7.1", "10.10", "8.0"], invalid: ["8", "8.", ".4", "8.4.1", "8.x", "v8.4", "8,4", "8.4 ", "8.4\n", "123.4"] },
  nodejsVersion: { valid: ["22", "8", "99"], invalid: ["", "100", "22.1", "v22", "2 2", "22\n", "x"] },
  pythonVersion: { valid: ["3.12", "3.9", "2.7"], invalid: ["3", "3.", "3.123", "12.3", "3.x", "python3.12", "3.12\n"] },
  fileMode: { valid: ["770", "0660", "755", "0750", "750", "644", "0644", "700", "775", "555", "000", "751", "754"], invalid: ["77", "78", "99999", "7 7", "rwx", "770\n", "", "-770", "777", "0777", "666", "772", "773", "776", "1770", "2770", "4755", "6755", "7777", "1755", "00755", "0o755", "7700"] },
  relativePath: { valid: [".", "htdocs", "htdocs/www.example.com", "a/b/c", "_x", "a.b", "a-b/c_d"], invalid: ["", "/", "/etc", "..", "../x", "a/..", "a/../b", ".hidden", "a/.hidden", "a//b", "a/", "a b", "a;b", "~", "-x", "./a", "a/./b"] },
  cacheTag: { valid: ["tag1", "a_b-c", "_x", "T"], invalid: ["", "-x", "a b", "a,b", "a;b", "a".repeat(65), "x\n"] },
};

describe("every value pattern", () => {
  for (const [name, cases] of Object.entries(CASES) as [PatternName, { valid: string[]; invalid: string[] }][]) {
    it(`${name}: accepts the documented shapes and rejects the wrong ones`, () => {
      for (const value of cases.valid) assert.ok(RE[name].test(value), `${name} should accept ${JSON.stringify(value)}`);
      for (const value of cases.invalid) assert.ok(!RE[name].test(value), `${name} should reject ${JSON.stringify(value)}`);
    });
  }

  it("covers every pattern with explicit cases", () => {
    assert.deepEqual(Object.keys(CASES).sort(), Object.keys(SOURCES).sort());
  });

  it("is anchored: a valid value with a hostile prefix or suffix is rejected", () => {
    for (const [name, cases] of Object.entries(CASES) as [PatternName, { valid: string[]; invalid: string[] }][]) {
      for (const value of cases.valid.slice(0, 3)) {
        for (const junk of ["\n", ";id", " ", "'", "\u0000", "\r\n"]) {
          assert.ok(!RE[name].test(value + junk) || (junk === " " && (name === "person" || name === "templateName") && /[a-z]$/i.test(value) === false), `${name}: ${JSON.stringify(value + junk)}`);
          assert.ok(!RE[name].test(junk + value), `${name}: ${JSON.stringify(junk + value)}`);
        }
      }
    }
  });

  it("never accepts anything from the hostile corpus that carries a shell-significant character", () => {
    for (const [name, source] of Object.entries(SOURCES)) {
      const re = new RegExp(source);
      for (const value of HOSTILE) {
        if (!re.test(value)) continue;
        const spaceOk = name === "templateName" || name === "person";
        const text = spaceOk ? value.replaceAll(" ", "_") : value;
        assert.ok(!FORBIDDEN_IN_VALUES.test(text) && !(!spaceOk && value.includes(" ")), `${name} accepted ${JSON.stringify(value)}`);
      }
    }
  });

  for (const name of Object.keys(SOURCES) as PatternName[]) {
    it(`property: every ${name} the pattern accepts is made of safe characters only`, () => {
      const re = RE[name];
      fc.assert(
        fc.property(fc.stringMatching(re), (value) => {
          assert.ok(re.test(value));
          const spaceOk = name === "templateName" || name === "person";
          const text = spaceOk ? value.replaceAll(" ", "_") : value;
          assert.ok(!FORBIDDEN_IN_VALUES.test(text), JSON.stringify(value));
          assert.ok(spaceOk || !value.includes(" "), JSON.stringify(value));
        }),
        { numRuns: 400 },
      );
    });

    it(`property: random strings never get through ${name} unless they contain only safe characters`, () => {
      const re = RE[name];
      fc.assert(
        fc.property(fc.string({ unit: "binary", maxLength: 80 }), (value) => {
          if (!re.test(value)) return;
          const spaceOk = name === "templateName" || name === "person";
          const text = spaceOk ? value.replaceAll(" ", "_") : value;
          assert.ok(!FORBIDDEN_IN_VALUES.test(text), JSON.stringify(value));
        }),
        { numRuns: 1500 },
      );
    });
  }

  it("property: values that start with a hyphen are only ever accepted where a hyphen is a legal first character", () => {
    for (const name of Object.keys(SOURCES) as PatternName[]) {
      fc.assert(fc.property(fc.stringMatching(/^-[A-Za-z0-9 ._:\/,@+-]{0,30}$/), (value) => !RE[name].test(value)), { numRuns: 200 });
    }
  });
});

describe("domains", () => {
  it("accepts at most 253 characters and 63 per label", () => {
    assert.ok(isDomain(`${"a".repeat(63)}.example.com`));
    assert.ok(!isDomain(`${"a".repeat(64)}.example.com`));
    const long = `${"a".repeat(60)}.`.repeat(4) + "com";
    assert.ok(long.length > 240);
    assert.ok(!isDomain(`${long}.${"b".repeat(20)}`));
  });
});

describe("application ports", () => {
  it("the hard floor refuses privileged, out-of-range and sensitive ports whatever a profile lists", () => {
    for (const p of [1024, 3000, 8000, 8080, 39400, 65535]) assert.ok(isPortAllowedAtAll(p), String(p));
    for (const p of [0, 1, 22, 80, 443, 1023, 65536, -1, 3000.5, Number.NaN, ...DENIED_APP_PORTS]) assert.ok(!isPortAllowedAtAll(p), String(p));
    assert.ok(!appPortSchema.safeParse("3000").success);
    assert.ok(appPortSchema.safeParse(3000).success);
    assert.ok(!appPortSchema.safeParse(3306).success);
  });
  it("a profile's list narrows it further: the default list is the usual web-app ports only", () => {
    for (const p of [1337, 2368, 3000, 3999, 4000, 4999, 5000, 5173, 8000, 8080, 8199]) assert.ok(isAppPort(p, DEFAULT_APP_PORTS), String(p));
    for (const p of [1024, 1336, 2369, 2999, 5001, 5172, 5174, 7999, 8200, 9000, 9090, 39400, 65535, ...DENIED_APP_PORTS]) assert.ok(!isAppPort(p, DEFAULT_APP_PORTS), String(p));
    assert.ok(DEFAULT_APP_PORTS.every((r) => r.from <= r.to));
  });
  it("a listed range never reaches a denied port", () => {
    const wide: PortRange[] = [{ from: 1024, to: 65535 }];
    for (const p of DENIED_APP_PORTS) assert.ok(!isAppPort(p, wide), String(p));
    assert.ok(isAppPort(9000, wide));
    assert.ok(!isAppPort(3000, []));
  });
  it("the denied ports include the databases, caches, queues and admin APIs a proxy must never publish", () => {
    for (const p of [2375, 2376, 3306, 5432, 6081, 6379, 8443, 9200, 11211, 27017, 5672, 15672, 9092, 6443, 10250]) assert.ok(DENIED_APP_PORTS.includes(p), String(p));
    // unauthenticated administration APIs and old services that sit inside the default ranges
    for (const p of [3389, 3690, 4369, 4505, 4506, 4646, 8001, 8086, 8200, 8500, 9090, 9100, 10255]) assert.ok(DENIED_APP_PORTS.includes(p), String(p));
    for (const p of DENIED_APP_PORTS) assert.ok(!isAppPort(p, DEFAULT_APP_PORTS), `${p} is allowed by no default range`);
  });
  it("writes ranges the way configuration files and the gate do", () => {
    assert.equal(portRangeText({ from: 5173, to: 5173 }), "5173");
    assert.equal(portRangeText({ from: 3000, to: 4999 }), "3000-4999");
    assert.equal(portRangesText(DEFAULT_APP_PORTS), "1337, 2368, 3000-4999, 5000, 5173, 8000-8199");
  });
});

describe("server paths", () => {
  const dirs = ["/var/lib/cloudpanel-mcp-server"];
  it("isCleanPath refuses traversal, doubled and trailing slashes, and odd characters", () => {
    for (const ok of ["/a", "/var/lib/x/y.sql", "/a/b-c_d.e"]) assert.ok(isCleanPath(ok), ok);
    for (const bad of ["a", "/", "/a/", "/a/.", "/a/..", "/a/../b", "/a//b", "/a/./b", "/a b", "/a'b", "/a\n", "/a;b", ""]) assert.ok(!isCleanPath(bad), JSON.stringify(bad));
  });
  it("isUnderDirs needs a real child and respects the directory boundary", () => {
    assert.ok(isUnderDirs("/var/lib/cloudpanel-mcp-server/a.sql", dirs));
    assert.ok(!isUnderDirs("/var/lib/cloudpanel-mcp-server", dirs));
    assert.ok(!isUnderDirs("/var/lib/cloudpanel-mcp-server/", dirs));
    assert.ok(!isUnderDirs("/var/lib/cloudpanel-mcp-server-evil/a.sql", dirs));
    assert.ok(!isUnderDirs("/var/lib/cloudpanel-mcp/a.sql", dirs));
    assert.ok(!isUnderDirs("/etc/passwd", dirs));
  });
  it("each kind of file has its own subdirectory and its own extensions", () => {
    const d = dirs[0];
    assert.deepEqual(FILE_KINDS, ["dump", "cert", "template"]);
    assert.deepEqual(kindDirs("dump", dirs), [`${d}/dumps`]);
    const ok: Record<string, string[]> = {
      dump: ["dumps/a.sql", "dumps/a.sql.gz", "dumps/x/y.sql"],
      cert: ["certs/a.key", "certs/a.pem", "certs/a.crt", "certs/a.cer", "certs/a.cert", "certs/a.chain", "certs/a.ca-bundle"],
      template: ["templates/a.tpl", "templates/a.conf"],
    };
    for (const kind of FILE_KINDS) {
      for (const file of ok[kind] ?? []) assert.ok(isKindPath(kind, `${d}/${file}`, dirs), `${kind} ${file}`);
      for (const other of FILE_KINDS.filter((k) => k !== kind)) {
        for (const file of ok[other] ?? []) assert.ok(!isKindPath(kind, `${d}/${file}`, dirs), `a ${other} file is not a ${kind} file: ${file}`);
      }
    }
  });
  it("a file of the wrong place, name or extension is refused, with a reason that names the rule and never the value", () => {
    const d = dirs[0];
    const bad: [string, string, string][] = [
      ["dump", `${d}/a.sql`, "must be inside"],
      ["dump", `${d}/certs/a.sql`, "must be inside"],
      ["dump", `${d}/dumps`, "must be inside"],
      ["dump", `${d}/dumps/`, "clean"],
      ["dump", `${d}/dumps/a.txt`, "must end with"],
      ["dump", `${d}/dumps/a.sql.bak`, "must end with"],
      ["dump", `${d}/dumps/a.sqlx`, "must end with"],
      ["dump", `${d}/dumps/../a.sql`, "clean"],
      ["dump", `${d}-evil/dumps/a.sql`, "must be inside"],
      ["dump", `${d}/dumps-x/a.sql`, "must be inside"],
      ["dump", "/tmp/dumps/a.sql", "must be inside"],
      ["cert", `${d}/certs/a.sql`, "must end with"],
      ["cert", `${d}/dumps/a.pem`, "must be inside"],
      ["template", `${d}/templates/a.pem`, "must end with"],
      ["template", `${d}/dumps/a.tpl`, "must be inside"],
    ];
    for (const [kind, path, expected] of bad) {
      const problem = kindPathProblem(kind as "dump", path, dirs);
      assert.ok(problem !== null && problem.includes(expected), `${kind} ${path}: ${problem}`);
      // a path that is itself an allowed directory is named by the rule, which is not an echo of a hostile value
      assert.ok(!problem.includes(path) || [...kindDirs("dump", dirs), ...kindDirs("cert", dirs), ...kindDirs("template", dirs)].includes(path), "the value is not echoed");
      assert.ok(!isKindPath(kind as "dump", path, dirs), path);
    }
    assert.equal(kindPathProblem("dump", `${d}/dumps/a.sql`, dirs), null);
    assert.ok(Object.values(FILE_EXT_TEXT).every((t) => t.startsWith(".")));
    assert.deepEqual(Object.values(FILE_SUBDIR).sort(), ["certs", "dumps", "templates"]);
  });
  it("several file directories each have their own subdirectories", () => {
    const two = ["/srv/a", "/srv/b"];
    assert.ok(isKindPath("dump", "/srv/b/dumps/x.sql", two));
    assert.ok(!isKindPath("dump", "/srv/c/dumps/x.sql", two));
    assert.ok(!isKindPath("dump", "/srv/a/certs/x.sql", two));
  });
  it("property: a path built from safe segments is clean and under its directory, and traversal never is", () => {
    fc.assert(
      fc.property(fc.array(fc.stringMatching(/^[A-Za-z0-9_][A-Za-z0-9_-]{0,10}$/), { minLength: 1, maxLength: 4 }), (parts) => {
        const path = `${dirs[0]}/${parts.join("/")}`;
        assert.ok(isCleanPath(path) && isUnderDirs(path, dirs));
        assert.ok(!isCleanPath(`${dirs[0]}/${parts.join("/")}/../x`));
      }),
      { numRuns: 200 },
    );
  });
});

describe("reverse-proxy URLs", () => {
  const hosts = ["127.0.0.1", "localhost", "::1"];
  it("parses scheme, host, port and path", () => {
    assert.deepEqual(parseProxyUrl("http://127.0.0.1:8000/app"), { scheme: "http", host: "127.0.0.1", port: 8000, path: "/app" });
    assert.deepEqual(parseProxyUrl("https://localhost"), { scheme: "https", host: "localhost", port: null, path: "" });
    assert.equal(parseProxyUrl("http://[::1]:3000")?.host, "::1");
  });
  it("refuses credentials, malformed ports and traversal (the shape only; the ports a profile allows are a policy)", () => {
    for (const bad of ["http://user@127.0.0.1", "http://127.0.0.1@evil.example.com", "http://127.0.0.1:80@evil.example.com/", "http://127.0.0.1:65536", "http://127.0.0.1:0", "http://127.0.0.1/..", "http://127.0.0.1//x", "ftp://127.0.0.1", "http://"]) {
      assert.equal(parseProxyUrl(bad), null, bad);
    }
    assert.ok(parseProxyUrl("http://127.0.0.1:80"));
    assert.ok(parseProxyUrl("http://127.0.0.1:443"));
    assert.equal(parseProxyUrl("http://127.0.0.1:22")?.port, 22);
  });
  it("only allows the configured hosts, exactly", () => {
    const ports = DEFAULT_APP_PORTS;
    assert.ok(isAllowedProxyUrl("http://127.0.0.1:8000", hosts, ports));
    assert.ok(isAllowedProxyUrl("http://[::1]:8000", hosts, ports));
    assert.ok(!isAllowedProxyUrl("http://10.0.0.5:8000", hosts, ports));
    assert.ok(!isAllowedProxyUrl("http://127.0.0.1.evil.example.com:8000", hosts, ports));
    assert.ok(!isAllowedProxyUrl("http://localhost.evil.example.com", hosts, ports));
    assert.ok(!isAllowedProxyUrl("http://evil.example.com", hosts, ports));
  });
  it("allows 80, 443 and the profile's application ports, and nothing else on a port", () => {
    const ports = DEFAULT_APP_PORTS;
    for (const url of ["http://127.0.0.1", "http://127.0.0.1:80", "http://127.0.0.1:443", "https://localhost:3000/app", "http://127.0.0.1:8080", "http://127.0.0.1:5173"]) assert.ok(isAllowedProxyUrl(url, hosts, ports), url);
    for (const url of ["http://127.0.0.1:22", "http://127.0.0.1:3306", "http://127.0.0.1:2375", "http://127.0.0.1:8443", "http://127.0.0.1:9000", "http://127.0.0.1:1024", "http://127.0.0.1:39400", "http://127.0.0.1:6379"]) assert.ok(!isAllowedProxyUrl(url, hosts, ports), url);
    assert.ok(isAllowedProxyUrl("http://127.0.0.1:39400", hosts, [{ from: 39400, to: 39409 }]));
    assert.ok(!isAllowedProxyUrl("http://127.0.0.1:3306", hosts, [{ from: 1024, to: 65535 }]), "the denied ports stay denied");
  });
  it("says which rule failed, without echoing the URL", () => {
    assert.match(String(proxyUrlProblem("ftp://x", hosts, DEFAULT_APP_PORTS)), /http\(s\):\/\/host/);
    assert.match(String(proxyUrlProblem("http://evil.example.com", hosts, DEFAULT_APP_PORTS)), /upstream host must be one of/);
    assert.match(String(proxyUrlProblem("http://127.0.0.1:3306", hosts, DEFAULT_APP_PORTS)), /upstream port must be 80, 443 or an allowed application port/);
    assert.equal(proxyUrlProblem("http://127.0.0.1:8000", hosts, DEFAULT_APP_PORTS), null);
  });
});

describe("purge targets", () => {
  it("parsePurge accepts all, tags and one URL", () => {
    assert.deepEqual(parsePurge("all"), { kind: "all" });
    assert.deepEqual(parsePurge("a,b_c"), { kind: "tags", tags: ["a", "b_c"] });
    assert.deepEqual(parsePurge("https://www.example.com/page.html"), { kind: "url", host: "www.example.com" });
    assert.deepEqual(parsePurge("ALL"), { kind: "tags", tags: ["ALL"] }); // only the exact word "all" means everything
  });
  it("refuses everything else", () => {
    for (const bad of ["", "all,a", "a,,b", ",a", "a,", "-a", "a b", "https://www.example.com:8443/x", "https://127.0.0.1/x", "https://www.example.com/x?y=1", "ftp://www.example.com", Array.from({ length: 21 }, (_, i) => `t${i}`).join(",")]) {
      assert.equal(parsePurge(bad), null, JSON.stringify(bad));
    }
    assert.ok(!purgeSchema.safeParse("x;id").success);
  });
});

describe("zod schemas", () => {
  it("refuse reserved site users and system databases", () => {
    for (const user of ["root", "clp", "admin", "www-data", "mysql", "nginx"]) assert.ok(!siteUserSchema.safeParse(user).success, user);
    assert.ok(siteUserSchema.safeParse("shop").success);
    for (const db of ["mysql", "sys", "information_schema", "performance_schema", "clp", "cloudpanel", "MySQL", "SYS", "CLP"]) assert.ok(!userDbNameSchema.safeParse(db).success, db);
    assert.ok(["clp", "cloudpanel"].every((db) => RESERVED_DATABASES.includes(db)), "the panel's own database is reserved");
  });
  it("dbUserSchema and the option type refuse the accounts that belong to the system, in any case", () => {
    for (const user of RESERVED_DB_USERS) {
      for (const form of [user, user.toUpperCase(), user[0]!.toUpperCase() + user.slice(1)]) {
        assert.ok(!dbUserSchema.safeParse(form).success, form);
        assert.equal(isValidOption("dbUser", form, CTX), false, form);
      }
    }
    for (const user of ["root", "mysql", "clp", "debian_sys_maint", "mysql_sys", "sys"]) assert.ok(RESERVED_DB_USERS.includes(user), user);
    for (const user of ["shop_user", "rooty", "myroot", "mysql2", "app_1"]) {
      assert.ok(dbUserSchema.safeParse(user).success, user);
      assert.equal(isValidOption("dbUser", user, CTX), true, user);
    }
    assert.ok(userDbNameSchema.safeParse("shopdb").success);
    assert.ok(dbNameSchema.safeParse("mysql").success); // a plain name is fine where nothing destructive happens
  });

  it("never echo the offending value in an error message", () => {
    const schemas = [domainSchema, siteUserSchema, dbNameSchema, panelUserSchema, fileModeSchema, relativePathSchema, purgeSchema];
    for (const schema of schemas) {
      for (const value of HOSTILE.filter((v) => v.length > 4 && !/^[A-Za-z0-9 .:-]+$/.test(v))) {
        const result = schema.safeParse(value);
        if (result.success) continue;
        const text = JSON.stringify(result.error.issues.map((i) => i.message));
        assert.ok(!text.includes(value) || value.length > 80 && !text.includes(value.slice(0, 40)), `echoed ${JSON.stringify(value)}`);
      }
    }
  });
});
