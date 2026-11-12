import assert from "node:assert/strict";
import { describe, it } from "node:test";
import fc from "fast-check";
import { ConfigError, DEFAULT_RATE_LIMITS, loadConfig, nodeVersionOk } from "../src/config/load.ts";
import { DEFAULT_APP_PORTS } from "../src/validate/patterns.ts";
import { defaultConfigPath, defaultStateDir, expandHome } from "../src/config/paths.ts";

const HOME = "/home/tester";

function fromFile(json: unknown, env: Record<string, string> = {}, mode = 0o100600, platform: NodeJS.Platform = "linux") {
  return loadConfig({
    env: { CLOUDPANEL_MCP_CONFIG: "/etc-not-used/cfg.json", ...env },
    platform,
    home: HOME,
    readFile: () => (typeof json === "string" ? json : JSON.stringify(json)),
    fileMode: () => mode,
  });
}

function fromEnv(env: Record<string, string>, platform: NodeJS.Platform = "linux") {
  return loadConfig({ env, platform, home: HOME, fileMode: () => null });
}

const ONE = { profiles: { prod: { ssh: { host: "prod-alias" } } } };

describe("configuration file", () => {
  it("fills defaults for a minimal profile: read-only, sudo, ask, loopback proxies", () => {
    const config = fromFile(ONE);
    assert.equal(config.profiles.length, 1);
    const p = config.profiles[0]!;
    assert.equal(p.name, "prod");
    assert.deepEqual(p.target, { kind: "ssh", ssh: { host: "prod-alias", user: undefined, port: undefined, identityFile: undefined, configFile: undefined } });
    assert.equal(p.elevation, "sudo");
    assert.equal(p.clpctlPath, "/usr/bin/clpctl");
    assert.equal(p.allow.size, 0);
    assert.equal(p.approvalWrite, "ask");
    assert.deepEqual(p.proxyHosts, ["127.0.0.1", "localhost", "::1"]);
    assert.deepEqual(p.fileDirs, ["/var/lib/cloudpanel-mcp-server"]);
    assert.deepEqual(p.rateLimits, DEFAULT_RATE_LIMITS);
    assert.deepEqual(p.rateLimits.ask, { max: 30, perMinutes: 10 });
    assert.equal(p.timeouts.defaultMs, 120_000);
    assert.equal(p.timeouts.letsEncryptMs, 600_000);
    assert.equal(p.inventory.enabled, false);
    assert.equal(config.defaultProfile, "prod");
  });

  it("reads every setting", () => {
    const config = fromFile({
      profiles: {
        "my-server": {
          ssh: { host: "10.0.0.5", user: "deploy", port: 2222, identityFile: "~/.ssh/id_ed25519", configFile: "/home/tester/.ssh/cfg" },
          elevation: "none",
          clpctlPath: "/usr/local/bin/clpctl",
          allow: ["write", "admin", "write"],
          approval: { write: "client" },
          protect: { domains: ["panel.example.com", "*.shop.example.com"], siteUsers: ["shop"], databases: ["shopdb"], panelUsers: ["owner"] },
          fileDirs: ["/srv/cloudpanel/exchange"],
          proxyHosts: ["LocalHost", "::1", "app.internal"],
          siteUserAccess: { shop: "shop-alias", blog: { host: "blog-alias", port: 2200 } },
          inventory: { enabled: true, command: "/opt/clp/inventory" },
          rateLimits: { destructive: [1, 60], ask: [4, 5] },
          timeoutsSeconds: { default: 30, db: 900 },
        },
        other: { local: true },
      },
      defaultProfile: "other",
    });
    const p = config.profiles[0]!;
    assert.equal((p.target as { ssh: { identityFile: string } }).ssh.identityFile, "/home/tester/.ssh/id_ed25519");
    assert.deepEqual([...p.allow].sort(), ["admin", "write"]);
    assert.equal(p.approvalWrite, "client");
    assert.deepEqual(p.proxyHosts, ["localhost", "::1", "app.internal"]);
    assert.equal(p.siteUserAccess["blog"]?.port, 2200);
    assert.equal(p.siteUserAccess["shop"]?.host, "shop-alias");
    assert.deepEqual(p.rateLimits.destructive, { max: 1, perMinutes: 60 });
    assert.deepEqual(p.rateLimits.ask, { max: 4, perMinutes: 5 });
    assert.deepEqual(p.rateLimits.write, DEFAULT_RATE_LIMITS.write);
    assert.equal(p.timeouts.defaultMs, 30_000);
    assert.equal(p.timeouts.dbMs, 900_000);
    assert.equal(p.inventory.command, "/opt/clp/inventory");
    assert.equal(config.profiles[1]!.target.kind, "local");
    assert.equal(config.defaultProfile, "other");
  });

  it("leaves the default empty when there are several profiles and none is named", () => {
    const config = fromFile({ profiles: { a: { local: true }, b: { local: true } } });
    assert.equal(config.defaultProfile, "");
  });

  const refusals: [string, unknown, RegExp][] = [
    ["unknown top-level key", { ...ONE, extra: 1 }, /unknown key/],
    ["unknown profile key", { profiles: { p: { ssh: { host: "h" }, allowAll: true } } }, /unknown key/],
    ["unknown ssh key", { profiles: { p: { ssh: { host: "h", proxy: "x" } } } }, /unknown key/],
    ["both ssh and local", { profiles: { p: { ssh: { host: "h" }, local: true } } }, /exactly one/],
    ["neither ssh nor local", { profiles: { p: {} } }, /exactly one/],
    ["no profiles", { profiles: {} }, /at least one/],
    ["bad profile name", { profiles: { "Prod!": { local: true } } }, /profile name/],
    ["ssh host starting with a dash", { profiles: { p: { ssh: { host: "-oProxyCommand=id" } } } }, /host/],
    ["ssh host with a space", { profiles: { p: { ssh: { host: "a b" } } } }, /host/],
    ["ssh user with a space", { profiles: { p: { ssh: { host: "h", user: "a b" } } } }, /account name/],
    ["ssh port zero", { profiles: { p: { ssh: { host: "h", port: 0 } } } }, /port|>=/],
    ["ssh port 70000", { profiles: { p: { ssh: { host: "h", port: 70000 } } } }, /port|<=/],
    ["relative identity file", { profiles: { p: { ssh: { host: "h", identityFile: "id_rsa" } } } }, /absolute/],
    ["unknown class", { profiles: { p: { local: true, allow: ["root"] } } }, /allow/],
    ["unknown elevation", { profiles: { p: { local: true, elevation: "su" } } }, /elevation/],
    ["bad approval", { profiles: { p: { local: true, approval: { write: "never" } } } }, /approval/],
    ["no approval switch for destructive", { profiles: { p: { local: true, approval: { destructive: "never" } } } }, /unknown key/],
    ["relative clpctl path", { profiles: { p: { local: true, clpctlPath: "clpctl" } } }, /clpctlPath/],
    ["clpctl path with traversal", { profiles: { p: { local: true, clpctlPath: "/usr/bin/../x" } } }, /clpctlPath/],
    ["fileDirs one level deep", { profiles: { p: { local: true, fileDirs: ["/data"] } } }, /two levels/],
    ["fileDirs trailing slash", { profiles: { p: { local: true, fileDirs: ["/data/x/"] } } }, /two levels/],
    ["fileDirs in /etc", { profiles: { p: { local: true, fileDirs: ["/etc/nginx"] } } }, /must not be inside/],
    ["fileDirs in /root", { profiles: { p: { local: true, fileDirs: ["/root/x"] } } }, /must not be inside/],
    ["fileDirs in /usr", { profiles: { p: { local: true, fileDirs: ["/usr/local/x"] } } }, /must not be inside/],
    ["fileDirs traversal", { profiles: { p: { local: true, fileDirs: ["/data/../etc"] } } }, /two levels/],
    ["empty fileDirs", { profiles: { p: { local: true, fileDirs: [] } } }, /fileDirs/],
    ["fileDirs in a home directory", { profiles: { p: { local: true, fileDirs: ["/home/deploy/mcp"] } } }, /other accounts can write there/],
    ["fileDirs in /tmp", { profiles: { p: { local: true, fileDirs: ["/tmp/mcp/files"] } } }, /other accounts can write there/],
    ["fileDirs in /var/tmp", { profiles: { p: { local: true, fileDirs: ["/var/tmp/mcp"] } } }, /other accounts can write there/],
    ["fileDirs in /var/www", { profiles: { p: { local: true, fileDirs: ["/var/www/mcp"] } } }, /other accounts can write there/],
    ["fileDirs on /mnt", { profiles: { p: { local: true, fileDirs: ["/mnt/data/mcp"] } } }, /other accounts can write there/],
    ["fileDirs on /media", { profiles: { p: { local: true, fileDirs: ["/media/usb/mcp"] } } }, /other accounts can write there/],
    ["allowUntrustedFileDirs as text", { profiles: { p: { local: true, allowUntrustedFileDirs: "yes" } } }, /allowUntrustedFileDirs/],
    ["proxy host with a scheme", { profiles: { p: { local: true, proxyHosts: ["http://x"] } } }, /host name/],
    ["proxy host with brackets", { profiles: { p: { local: true, proxyHosts: ["[::1]"] } } }, /host name/],
    ["protect domain uppercase", { profiles: { p: { local: true, protect: { domains: ["Panel.example.com"] } } } }, /lowercase domain/],
    ["protect domain bad wildcard", { profiles: { p: { local: true, protect: { domains: ["*example.com"] } } } }, /lowercase domain/],
    ["protect wildcard in the middle", { profiles: { p: { local: true, protect: { domains: ["a.*.example.com"] } } } }, /lowercase domain/],
    ["protect user with a space", { profiles: { p: { local: true, protect: { panelUsers: ["a b"] } } } }, /panel user/],
    ["site user access with a bad user", { profiles: { p: { local: true, siteUserAccess: { "Bad User": "x" } } } }, /site user/],
    ["site user access with a bad host", { profiles: { p: { local: true, siteUserAccess: { shop: "-x" } } } }, /host/],
    ["site user access logging in as root", { profiles: { p: { local: true, siteUserAccess: { shop: { host: "h", user: "root" } } } } }, /must be the site user itself \(shop\)/],
    ["site user access logging in as another site user", { profiles: { p: { local: true, siteUserAccess: { shop: { host: "h", user: "other" } } } } }, /must be the site user itself/],
    ["rate limit of zero", { profiles: { p: { local: true, rateLimits: { write: [0, 10] } } } }, /rateLimits|>=/],
    ["rate limit as an object", { profiles: { p: { local: true, rateLimits: { write: { max: 1 } } } } }, /rateLimits/],
    ["timeout too small", { profiles: { p: { local: true, timeoutsSeconds: { default: 1 } } } }, /timeoutsSeconds|>=/],
    ["appPorts empty", { profiles: { p: { local: true, appPorts: [] } } }, /appPorts/],
    ["appPorts privileged", { profiles: { p: { local: true, appPorts: [80] } } }, /1024 to 65535/],
    ["appPorts too large", { profiles: { p: { local: true, appPorts: [70000] } } }, /appPorts\[0\]/],
    ["appPorts text", { profiles: { p: { local: true, appPorts: ["http"] } } }, /port such as/],
    ["appPorts decimal", { profiles: { p: { local: true, appPorts: [3000.5] } } }, /port such as/],
    ["appPorts reversed range", { profiles: { p: { local: true, appPorts: ["4000-3000"] } } }, /upward/],
    ["appPorts range into the privileged ports", { profiles: { p: { local: true, appPorts: ["80-3000"] } } }, /1024 to 65535/],
    ["appPorts open range", { profiles: { p: { local: true, appPorts: ["3000-"] } } }, /port such as/],
    ["appPorts a denied database port", { profiles: { p: { local: true, appPorts: [3000, 3306] } } }, /port 3306 is never allowed/],
    ["appPorts a denied admin port", { profiles: { p: { local: true, appPorts: ["8443"] } } }, /port 8443 is never allowed/],
    ["unknown default profile", { ...ONE, defaultProfile: "nope" }, /defaultProfile/],
    ["inventory command relative", { profiles: { p: { local: true, inventory: { enabled: true, command: "inv" } } } }, /inventory/],
  ];
  for (const [name, json, pattern] of refusals) {
    it(`refuses: ${name}`, () => {
      assert.throws(() => fromFile(json), (e: unknown) => e instanceof ConfigError && pattern.test(e.message), name);
    });
  }

  it("refuses text that is not JSON without echoing it, whatever the parser says", () => {
    for (const text of ["{ not json SECRET-VALUE", "SECRET-VALUE-XYZ", '{"profiles": SECRET-VALUE-XYZ}', '{"profiles": {"p": {"local": true}}} SECRET-VALUE-XYZ', "'SECRET-VALUE-XYZ'", "\u0000SECRET-VALUE-XYZ"]) {
      assert.throws(() => fromFile(text), (e: unknown) => e instanceof ConfigError && /not valid JSON/.test(e.message) && !e.message.includes("SECRET"), text);
    }
  });

  it("refuses a config file that others can write, but not on Windows", () => {
    for (const mode of [0o100666, 0o100620, 0o100602, 0o100777]) {
      assert.throws(() => fromFile(ONE, {}, mode), /writable by group or others/);
    }
    for (const mode of [0o100600, 0o100640, 0o100644, 0o100400]) assert.doesNotThrow(() => fromFile(ONE, {}, mode));
    assert.doesNotThrow(() => fromFile(ONE, {}, 0o100666, "win32"));
  });

  it("property: arbitrary JSON never makes the loader throw anything but ConfigError", () => {
    fc.assert(
      fc.property(fc.json(), (text) => {
        try {
          fromFile(text);
        } catch (error) {
          assert.ok(error instanceof ConfigError, String(error));
        }
      }),
      { numRuns: 400 },
    );
    fc.assert(
      fc.property(fc.anything({ maxDepth: 4 }), (value) => {
        try {
          fromFile({ profiles: { p: value } });
        } catch (error) {
          assert.ok(error instanceof ConfigError, String(error));
        }
      }),
      { numRuns: 400 },
    );
  });
});

describe("file directories", () => {
  const dirs = (fileDirs: string[], extra: Record<string, unknown> = {}) => fromFile({ profiles: { p: { local: true, fileDirs, ...extra } } }).profiles[0]!;

  it("accept root-owned places and refuse the places other accounts can write", () => {
    for (const ok of ["/var/lib/cloudpanel-mcp-server", "/srv/cloudpanel/exchange", "/opt/cloudpanel-mcp/files", "/var/cache/mcp/files", "/home-backup/x/y", "/tmpx/a/b"]) {
      assert.deepEqual(dirs([ok]).fileDirs, [ok], ok);
    }
    for (const bad of ["/home/shop/mcp", "/home/shop", "/tmp/a/b", "/var/tmp/a", "/var/www/a/b", "/var/mail/a", "/mnt/x/y", "/media/x/y", "/var/lock/mcp", "/var/crash/mcp", "/var/spool/mail", "/var/lib/php/sessions"]) {
      assert.throws(() => dirs([bad]), /other accounts can write there/, bad);
    }
  });
  it("allowUntrustedFileDirs lets a throw-away server use them, and the profile says so", () => {
    const p = dirs(["/home/deploy/mcp-contract-test"], { allowUntrustedFileDirs: true });
    assert.deepEqual(p.fileDirs, ["/home/deploy/mcp-contract-test"]);
    assert.equal(p.allowUntrustedFileDirs, true);
    assert.equal(dirs(["/var/lib/x/y"]).allowUntrustedFileDirs, false);
  });
  it("a site user's ssh login may name that user, and an alias carries no user to check", () => {
    const p = fromFile({ profiles: { p: { local: true, siteUserAccess: { shop: { host: "h", user: "shop" }, blog: "blog-alias" } } } }).profiles[0]!;
    assert.equal(p.siteUserAccess["shop"]?.user, "shop");
    assert.equal(p.siteUserAccess["blog"]?.user, undefined);
  });
  it("allowUntrustedFileDirs does not lift the system directories", () => {
    for (const bad of ["/etc/x/y", "/root/x", "/usr/local/x", "/dev/shm/x", "/run/x/y", "/var/run/mcp"]) {
      assert.throws(() => dirs([bad], { allowUntrustedFileDirs: true }), /must not be inside/, bad);
    }
  });
});

describe("application ports", () => {
  it("default to the usual web-app ports", () => {
    assert.deepEqual(fromFile(ONE).profiles[0]!.appPorts, DEFAULT_APP_PORTS);
  });
  it("take single ports and low-high ranges, as numbers or text", () => {
    const p = fromFile({ profiles: { p: { local: true, appPorts: [3000, "4000-4999", "5173", 39400] } } }).profiles[0]!;
    assert.deepEqual(p.appPorts, [{ from: 3000, to: 3000 }, { from: 4000, to: 4999 }, { from: 5173, to: 5173 }, { from: 39400, to: 39400 }]);
  });
  it("accept a wide range: the denied ports are left out at the point of use, not by rewriting the list", () => {
    const p = fromFile({ profiles: { p: { local: true, appPorts: ["1024-65535"] } } }).profiles[0]!;
    assert.deepEqual(p.appPorts, [{ from: 1024, to: 65535 }]);
  });
  it("come from CLOUDPANEL_MCP_APP_PORTS in the quick start", () => {
    const p = fromEnv({ CLOUDPANEL_MCP_LOCAL: "1", CLOUDPANEL_MCP_APP_PORTS: "3000-3999, 5173" }).profiles[0]!;
    assert.deepEqual(p.appPorts, [{ from: 3000, to: 3999 }, { from: 5173, to: 5173 }]);
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_LOCAL: "1", CLOUDPANEL_MCP_APP_PORTS: "3306" }), /never allowed/);
  });
});

describe("environment quick start", () => {
  it("builds one profile named default from CLOUDPANEL_MCP_* variables", () => {
    const config = fromEnv({
      CLOUDPANEL_MCP_SSH_HOST: "my-server",
      CLOUDPANEL_MCP_SSH_USER: "deploy",
      CLOUDPANEL_MCP_SSH_PORT: "2222",
      CLOUDPANEL_MCP_ALLOW: "write, destructive",
      CLOUDPANEL_MCP_PROTECT_DOMAINS: "panel.example.com,*.prod.example.com",
      CLOUDPANEL_MCP_APPROVAL_WRITE: "client",
      CLOUDPANEL_MCP_STATE_DIR: "/tmp/state-x",
    });
    const p = config.profiles[0]!;
    assert.equal(p.name, "default");
    assert.equal((p.target as { ssh: { port: number } }).ssh.port, 2222);
    assert.deepEqual([...p.allow], ["write", "destructive"]);
    assert.deepEqual(p.protect.domains, ["panel.example.com", "*.prod.example.com"]);
    assert.equal(p.approvalWrite, "client");
    assert.equal(config.stateDir, "/tmp/state-x");
    assert.equal(config.source, "environment variables");
  });

  it("supports a local profile and a custom name", () => {
    const config = fromEnv({ CLOUDPANEL_MCP_LOCAL: "1", CLOUDPANEL_MCP_PROFILE: "here", CLOUDPANEL_MCP_ELEVATION: "none", CLOUDPANEL_MCP_INVENTORY: "1" });
    assert.equal(config.profiles[0]!.name, "here");
    assert.equal(config.profiles[0]!.target.kind, "local");
    assert.equal(config.profiles[0]!.inventory.enabled, true);
  });

  it("fails closed on a misspelt variable instead of ignoring it", () => {
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_SSH_HOST: "h", CLOUDPANEL_MCP_ALOW: "write" }), /unknown environment variable CLOUDPANEL_MCP_ALOW/);
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_SSH_HOST: "h", CLOUDPANEL_MCP_PROTECT_DOMAIN: "a.example.com" }), /unknown environment variable/);
  });

  it("refuses a bad flag, a bad port and a missing server", () => {
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_LOCAL: "yes" }), /must be 0 or 1/);
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_SSH_HOST: "h", CLOUDPANEL_MCP_SSH_PORT: "abc" }), ConfigError);
    assert.throws(() => fromEnv({}), /no profile configured/);
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_CONFIG: "/nowhere/x.json" }), /does not exist/);
  });

  it("refuses a relative state directory", () => {
    assert.throws(() => fromEnv({ CLOUDPANEL_MCP_LOCAL: "1", CLOUDPANEL_MCP_STATE_DIR: "relative/dir" }), /absolute/);
  });
});

describe("paths", () => {
  it("picks the platform's state and config directories", () => {
    assert.equal(defaultStateDir({}, "linux", HOME), "/home/tester/.local/state/cloudpanel-mcp-server");
    assert.equal(defaultStateDir({ XDG_STATE_HOME: "/x/state" }, "linux", HOME), "/x/state/cloudpanel-mcp-server");
    assert.equal(defaultStateDir({ XDG_STATE_HOME: "relative" }, "linux", HOME), "/home/tester/.local/state/cloudpanel-mcp-server");
    assert.equal(defaultStateDir({}, "darwin", HOME), "/home/tester/Library/Application Support/cloudpanel-mcp-server");
    assert.match(defaultStateDir({ LOCALAPPDATA: "C:\\L" }, "win32", HOME), /cloudpanel-mcp-server$/);
    assert.equal(defaultConfigPath({}, "linux", HOME), "/home/tester/.config/cloudpanel-mcp-server/config.json");
    assert.equal(defaultConfigPath({ XDG_CONFIG_HOME: "/x/cfg" }, "linux", HOME), "/x/cfg/cloudpanel-mcp-server/config.json");
    assert.equal(defaultConfigPath({}, "darwin", HOME), "/home/tester/Library/Application Support/cloudpanel-mcp-server/config.json");
  });
  it("expands ~ only at the start", () => {
    assert.equal(expandHome("~", HOME), HOME);
    assert.equal(expandHome("~/a/b", HOME, "linux"), "/home/tester/a/b");
    assert.equal(expandHome("/x/~/y", HOME), "/x/~/y");
    assert.equal(expandHome("~root/x", HOME), "~root/x");
  });
});

describe("node version", () => {
  it("needs 22 or newer", () => {
    assert.ok(nodeVersionOk("22.0.0") && nodeVersionOk("24.21.0") && nodeVersionOk("30.1.2"));
    assert.ok(!nodeVersionOk("20.19.0") && !nodeVersionOk("18.0.0") && !nodeVersionOk("x") && !nodeVersionOk(""));
  });
});
