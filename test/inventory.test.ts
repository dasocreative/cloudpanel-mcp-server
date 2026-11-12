import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { IS_WINDOWS, ROOT, shortTmp, writeExecutable } from "./helpers.ts";

const SCRIPT = readFileSync(join(ROOT, "inventory", "cloudpanel-mcp-inventory"), "utf8");
const SHELLS = ["/bin/sh", "/bin/dash", "/bin/bash"].filter(existsSync);
const HAS_OPENSSL = spawnSync("openssl", ["version"]).status === 0;

// Vhosts reconstructed from the templates printed in CloudPanel's documentation (not recorded from a server).
const PHP = `server {
  listen 80;
  listen [::]:80;
  server_name example.com;
  return 301 https://www.example.com$request_uri;
}
server {
  listen 80;
  listen [::]:80;
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  ssl_certificate_key /etc/nginx/ssl-certificates/www.example.com.key;
  ssl_certificate /etc/nginx/ssl-certificates/www.example.com.crt;
  # server_name hidden.example.com;
  # note; server_name smuggled.example.com; root /home/smuggled/htdocs/smuggled.example.com;
  # } server {
  server_name www.example.com;
  root /home/shop/htdocs/www.example.com;
  access_log /home/shop/logs/nginx/access.log main;
  location ~ \\.php$ {
    include fastcgi_params;
    fastcgi_pass 127.0.0.1:18001;
    fastcgi_param PHP_VALUE "memory_limit=256M";
  }
}
`;
const NODE = `server {
  listen 443 ssl http2;
  ssl_certificate /etc/nginx/ssl-certificates/app.example.com.crt;
  server_name app.example.com api.example.com;
  root /home/appuser/htdocs/app.example.com;
  location / {
    proxy_pass http://127.0.0.1:3000/;
    proxy_set_header Host $http_host;
  }
}
`;
const STATIC = `server {
  listen 443 ssl;
  server_name static.example.com;
  root /home/staticsite/htdocs/static.example.com;
  index index.html;
}
`;
const PROXY = `server {
  listen 443 ssl;
  server_name rp.example.com;
  root /home/rpuser/htdocs/rp.example.com;
  location / {
    proxy_pass http://[::1]:8000/app/;
  }
}
`;
const PANEL = `server {
  listen 8443 ssl http2;
  server_name _;
  root /home/clp/htdocs/app/public;
  location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm-clp.sock; }
}
`;
const TRAVERSAL = `server {
  listen 443 ssl;
  server_name t.example.com;
  root /home/evil/htdocs/../../../etc;
}
`;
const BACKSLASH = `server {
  listen 443 ssl;
  ssl_certificate @CERTS@/b.example.com.crt\\;
  server_name b.example.com;
  root /home/bslash/htdocs/b\\;
  location / { proxy_pass http://127.0.0.1:3000/a\\; }
}
`;
const HOSTILE = `server {
  listen 443 ssl;
  ssl_certificate /etc/shadow;
  server_name evil.example.com"; touch /tmp/pwn; " $(id) a.example.com\`id\`;
  root /home/evil/htdocs/x$(id)/../../etc;
  location / { proxy_pass http://127.0.0.1:3000/$(id)'"; }
}
`;

interface Rig { run(args?: string[], shell?: string): { status: number | null; stdout: string; stderr: string }; vhosts: string; certs: string }

function rig(files: Record<string, string>): Rig {
  const dir = shortTmp("clpi-");
  const vhosts = join(dir, "sites-enabled");
  const certs = join(dir, "ssl-certificates");
  mkdirSync(vhosts);
  mkdirSync(certs);
  for (const [name, content] of Object.entries(files)) writeFileSync(join(vhosts, name), content.replaceAll("@CERTS@", certs));
  const script = SCRIPT.replace(/^VHOST_DIR=.*$/m, () => `VHOST_DIR=${vhosts}`).replace(/^CERT_DIR=.*$/m, () => `CERT_DIR=${certs}`);
  assert.notEqual(script, SCRIPT);
  const path = writeExecutable(dir, "inventory", script);
  return {
    vhosts,
    certs,
    run(args = [], shell = SHELLS[0] as string) {
      const r = spawnSync(shell, [path, ...args], { encoding: "utf8", env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin" }, maxBuffer: 20 * 1024 * 1024 });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr };
    },
  };
}

const SAFE_OUTPUT = /^[A-Za-z0-9 ._:/,@+=[\]"{}:-]*$/;

describe("the inventory script", { skip: IS_WINDOWS }, () => {
  const sites = (r: Rig, shell?: string): Record<string, any>[] => {
    const out = r.run([], shell);
    assert.equal(out.status, 0, out.stderr);
    return (JSON.parse(out.stdout) as { sites: Record<string, any>[] }).sites;
  };

  for (const shell of SHELLS) {
    it(`lists sites with a guess of their type (${shell})`, () => {
      const r = rig({ "www.example.com.conf": PHP, "app.example.com.conf": NODE, "static.example.com.conf": STATIC, "rp.example.com.conf": PROXY, "default.conf": PANEL });
      const byFile = new Map(sites(r, shell).map((s) => [s["file"] as string, s]));
      assert.deepEqual(byFile.get("www.example.com.conf"), { domain: "www.example.com", aliases: [], kind: "php", siteUser: "shop", root: "/home/shop/htdocs/www.example.com", file: "www.example.com.conf" });
      assert.deepEqual(byFile.get("app.example.com.conf"), { domain: "app.example.com", aliases: ["api.example.com"], kind: "proxy", siteUser: "appuser", root: "/home/appuser/htdocs/app.example.com", upstream: "http://127.0.0.1:3000", file: "app.example.com.conf" });
      assert.deepEqual(byFile.get("static.example.com.conf"), { domain: "static.example.com", aliases: [], kind: "static", siteUser: "staticsite", root: "/home/staticsite/htdocs/static.example.com", file: "static.example.com.conf" });
      assert.equal(byFile.get("rp.example.com.conf")?.["upstream"], "http://[::1]:8000/app");
      assert.equal(byFile.get("default.conf")?.["kind"], "panel");
      assert.equal(byFile.size, 5);
    });
  }

  it("prints the document of the expected shape and is the same on every run", () => {
    const r = rig({ "a.conf": STATIC });
    const first = r.run().stdout;
    assert.equal(first, r.run().stdout);
    const doc = JSON.parse(first) as Record<string, unknown>;
    assert.equal(doc["generator"], "cloudpanel-mcp-inventory");
    assert.equal(doc["unofficial"], true);
    assert.equal(doc["version"], 1);
  });

  it("refuses every argument", () => {
    const r = rig({ "a.conf": STATIC });
    for (const args of [["x"], ["--help"], [""], ["a", "b"], ["/etc/shadow"], ["-c", "id"]]) {
      const out = r.run(args);
      assert.equal(out.status, 2, JSON.stringify(args));
      assert.equal(out.stdout, "");
    }
  });

  it("prints only values that passed a pattern, whatever the vhost contains", () => {
    const r = rig({ "evil.conf": HOSTILE, "ok.conf": STATIC, "garbage.conf": "\u0000\u0001\u0002 server { \n } } {{{ \u001b[31m", "empty.conf": "" });
    const out = r.run();
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout.trimEnd(), SAFE_OUTPUT);
    const found = (JSON.parse(out.stdout) as { sites: { domain: string; file: string; root?: string; upstream?: string }[] }).sites;
    const evil = found.find((s) => s.file === "evil.conf");
    assert.ok(evil === undefined || (evil.root === undefined && evil.upstream === undefined), JSON.stringify(evil));
    assert.ok(!out.stdout.includes("pwn") && !out.stdout.includes("$(") && !out.stdout.includes("shadow"));
    assert.ok(found.some((s) => s.file === "ok.conf"));
  });

  it("never prints a backslash: awk implementations differ on one inside a bracket expression, and a trailing one would break the JSON", () => {
    const r = rig({ "b.conf": BACKSLASH, "ok.conf": STATIC });
    const out = r.run();
    assert.equal(out.status, 0, out.stderr);
    assert.ok(!out.stdout.includes("\\"), out.stdout);
    const found = (JSON.parse(out.stdout) as { sites: { file: string; root?: string; upstream?: string; certificate?: string }[] }).sites;
    const b = found.find((s) => s.file === "b.conf");
    assert.ok(b === undefined || (b.root === undefined && b.upstream === undefined && b.certificate === undefined), JSON.stringify(b));
  });

  it("does not trust a root that climbs out of the site's directory", () => {
    const [site] = sites(rig({ "t.conf": TRAVERSAL }));
    assert.equal(site?.["domain"], "t.example.com");
    assert.equal(site?.["root"], undefined);
    assert.equal(site?.["siteUser"], undefined);
  });

  it("ignores commented directives, other files, directories and oversized files", () => {
    const r = rig({ "a.conf": PHP, "notes.txt": STATIC, "big.conf": `${STATIC}\n# ${"x".repeat(70_000)}\n` });
    mkdirSync(join(r.vhosts, "dir.conf"));
    const found = sites(r);
    assert.deepEqual(found.map((s) => s["file"]), ["a.conf"]);
    assert.ok(!JSON.stringify(found).includes("hidden.example.com"));
  });

  it("reads at most 500 vhost files", () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 520; i += 1) files[`s${String(i).padStart(3, "0")}.conf`] = STATIC.replace("static.example.com", `s${i}.example.com`);
    assert.equal(sites(rig(files)).length, 500);
  });

  it("follows a symlink only to a regular file and prints nothing from a file that is not a vhost", () => {
    const r = rig({});
    writeFileSync(join(r.vhosts, "target.txt"), "root:x:0:0:root:/root:/bin/sh\n");
    symlinkSync(join(r.vhosts, "target.txt"), join(r.vhosts, "link.conf"));
    symlinkSync("/nonexistent/file", join(r.vhosts, "dangling.conf"));
    const out = r.run();
    assert.equal(out.status, 0);
    assert.deepEqual(JSON.parse(out.stdout).sites, []);
    assert.ok(!out.stdout.includes("root:x"));
  });

  it("writes nothing: no files appear, the directories keep their content", () => {
    const r = rig({ "a.conf": PHP });
    const before = readFileSync(join(r.vhosts, "a.conf"), "utf8");
    r.run();
    assert.equal(readFileSync(join(r.vhosts, "a.conf"), "utf8"), before);
    assert.ok(!SCRIPT.match(/>\s*[^&\s]*[A-Za-z/]/g)?.some((m) => !/>\s*\/dev\/null|>&2|2>|> *"?\$tmp/.test(m)), "only redirections to /dev/null or stderr");
  });

  it("states what it is, and contains no network or write command", () => {
    assert.match(SCRIPT, /UNOFFICIAL/);
    for (const forbidden of [/\bcurl\b/, /\bwget\b/, /\bnc\b/, /\brm\b/, /\bmv\b/, /\bcp\b/, /\btee\b/, /\bchmod\b/, /\bchown\b/, /\beval\b/, /\bsource\b/, /\.\s+\//]) {
      assert.ok(!forbidden.test(SCRIPT.replace(/^#.*$/gm, "")), String(forbidden));
    }
  });

  it("reports when a certificate in the certificate directory expires", { skip: !HAS_OPENSSL }, () => {
    const r = rig({ "www.example.com.conf": PHP.replaceAll("/etc/nginx/ssl-certificates", "@CERTS@") });
    for (const [name, days] of [["www.example.com", 10]] as const) {
      const k = join(r.certs, `${name}.key`);
      const c = join(r.certs, `${name}.crt`);
      const gen = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", k, "-out", c, "-days", String(days), "-subj", `/CN=${name}`], { encoding: "utf8" });
      assert.equal(gen.status, 0, gen.stderr);
    }
    const [site] = sites(r);
    assert.match(String(site?.["certificateExpires"]), /^[A-Z][a-z]{2} +\d{1,2} [\d:]{8} \d{4} GMT$/);
    assert.equal(site?.["certificateExpiresWithin30Days"], true);
  });

  it("never opens a certificate outside the certificate directory", { skip: !HAS_OPENSSL }, () => {
    const dir = shortTmp("clpi-");
    const outside = join(dir, "outside.crt");
    spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", join(dir, "o.key"), "-out", outside, "-days", "5", "-subj", "/CN=x"]);
    const r = rig({ "a.conf": PHP.replace("/etc/nginx/ssl-certificates/www.example.com.crt", outside) });
    const [site] = sites(r);
    assert.equal(site?.["certificateExpires"], undefined);
  });
});
