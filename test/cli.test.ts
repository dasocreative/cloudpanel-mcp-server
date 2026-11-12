import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { describe, it } from "node:test";
import { profileWarnings } from "../src/policy/warnings.ts";
import { DIST_ENTRY, makeProfile, shortTmp } from "./helpers.ts";

describe("profileWarnings", () => {
  const protect = (over: Record<string, string[]>) => ({ domains: [], siteUsers: [], databases: [], panelUsers: [], ...over });

  it("says that protected site users and databases do not survive the deletion of their site", () => {
    const w = profileWarnings(makeProfile({ protect: protect({ domains: ["panel.example.com"], siteUsers: ["shop"] }) }));
    assert.equal(w.length, 1);
    assert.match(w[0] as string, /protect the DOMAIN/);
    assert.equal(profileWarnings(makeProfile({ protect: protect({ domains: ["a.example.com"], databases: ["maindb"] }) })).length, 1);
  });
  it("says when destructive tools are on and no domain is protected", () => {
    const w = profileWarnings(makeProfile());
    assert.equal(w.length, 1);
    assert.match(w[0] as string, /no domain is protected/);
  });
  it("says when write tools rely on the client's own prompt", () => {
    const w = profileWarnings(makeProfile({ approvalWrite: "client", allow: new Set(["write"]) }));
    assert.equal(w.length, 1);
    assert.match(w[0] as string, /rely on the client/);
  });
  it("says when the file directories may be in places other accounts can write", () => {
    const w = profileWarnings(makeProfile({ allowUntrustedFileDirs: true, allow: new Set(["write"]) }));
    assert.equal(w.length, 1);
    assert.match(w[0] as string, /allowUntrustedFileDirs is on/);
  });
  it("says nothing about a careful profile", () => {
    assert.deepEqual(profileWarnings(makeProfile({ allow: new Set(["write"]), protect: protect({}) })), []);
    assert.deepEqual(profileWarnings(makeProfile({ protect: protect({ domains: ["panel.example.com"] }) })), []);
    assert.deepEqual(profileWarnings(makeProfile({ allow: new Set() })), []);
  });
});

describe("--check-config", { skip: !existsSync(DIST_ENTRY) }, () => {
  const run = (env: Record<string, string>) =>
    spawnSync(process.execPath, [DIST_ENTRY, "--check-config"], {
      encoding: "utf8",
      env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", HOME: shortTmp("clph-"), CLOUDPANEL_MCP_STATE_DIR: shortTmp("clps-"), ...env },
    });

  it("prints what the configuration means: protection, file places, ports and warnings", () => {
    const r = run({ CLOUDPANEL_MCP_LOCAL: "1", CLOUDPANEL_MCP_ALLOW: "write,destructive", CLOUDPANEL_MCP_PROTECT_DATABASES: "maindb", CLOUDPANEL_MCP_APP_PORTS: "3000-3999" });
    const text = r.stdout + r.stderr;
    assert.equal(r.status, 0, text);
    assert.match(text, /protected domains: \(none\)/);
    assert.match(text, /databases: maindb/);
    assert.match(text, /\/var\/lib\/cloudpanel-mcp-server\/dumps \[dumps\]/);
    assert.match(text, /\/var\/lib\/cloudpanel-mcp-server\/certs \[certs\]/);
    assert.match(text, /application ports: 3000-3999/);
    assert.match(text, /WARNING: .*protect the DOMAIN/);
    assert.match(text, /WARNING: .*no domain is protected/);
  });
  it("prints no warning for a careful profile", () => {
    const r = run({ CLOUDPANEL_MCP_LOCAL: "1", CLOUDPANEL_MCP_PROTECT_DOMAINS: "panel.example.com" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!/WARNING/.test(r.stdout + r.stderr));
  });
});
