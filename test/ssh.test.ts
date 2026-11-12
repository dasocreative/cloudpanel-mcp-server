import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { Detector } from "../src/detect.ts";
import { AuditLog } from "../src/audit.ts";
import { buildCatalog } from "../src/catalog/index.ts";
import { Engine } from "../src/engine.ts";
import { killActive, runProcess } from "../src/exec/process.ts";
import { CONTROL_PERSIST_SECONDS, LocalTransport, SshTransport, buildSshArgs, controlPathFits, controlSocketDir, defaultTransports, socketKeyOf } from "../src/exec/transport.ts";
import { RateLimiter } from "../src/policy/rate.ts";
import { PlanTokens } from "../src/policy/tokens.ts";
import { Redactor } from "../src/secrets/redact.ts";
import { SecretsStore } from "../src/secrets/store.ts";
import { FIXED_PASSWORD, FakeIO, IS_WINDOWS, SIM_DIR, approve, bodyOf, installSimClpctl, makeProfile, shortTmp, writeExecutable } from "./helpers.ts";
import type { SimState } from "./sim/clpctl.ts";

const OPTS = { stateDir: "/tmp/s", platform: "linux" as NodeJS.Platform };

describe("buildSshArgs", () => {
  it("builds the hardened argument list: no tty, batch mode, strict host keys, no forwarding, host then -- then the command", () => {
    const args = buildSshArgs({ host: "my-server" }, "sudo -n /usr/bin/clpctl", OPTS);
    assert.deepEqual(args.slice(0, 1), ["-T"]);
    for (const needed of ["BatchMode=yes", "StrictHostKeyChecking=yes", "ConnectTimeout=10", "ClearAllForwardings=yes", "ForwardAgent=no", "ForwardX11=no", "PermitLocalCommand=no"]) {
      assert.ok(args.includes(needed), needed);
    }
    assert.deepEqual(args.slice(-3), ["my-server", "--", "sudo -n /usr/bin/clpctl"]);
  });
  it("adds user, port, identity file and config file only when set, and pins the identity", () => {
    const args = buildSshArgs({ host: "10.0.0.5", user: "deploy", port: 2222, identityFile: "/k/id", configFile: "/c/cfg" }, "x", OPTS);
    assert.deepEqual(args.slice(args.indexOf("-F"), args.indexOf("-F") + 2), ["-F", "/c/cfg"]);
    assert.deepEqual(args.slice(args.indexOf("-p"), args.indexOf("-p") + 2), ["-p", "2222"]);
    assert.deepEqual(args.slice(args.indexOf("-l"), args.indexOf("-l") + 2), ["-l", "deploy"]);
    assert.deepEqual(args.slice(args.indexOf("-i"), args.indexOf("-i") + 4), ["-i", "/k/id", "-o", "IdentitiesOnly=yes"]);
    const plain = buildSshArgs({ host: "h" }, "x", OPTS);
    for (const flag of ["-F", "-p", "-l", "-i"]) assert.ok(!plain.includes(flag), flag);
  });
  it("refuses a host that could be read as an option or that holds whitespace", () => {
    for (const host of ["-oProxyCommand=id", "-x", "a b", "a\tb", "a\nb"]) assert.throws(() => buildSshArgs({ host }, "x", OPTS), /invalid ssh host/, JSON.stringify(host));
  });
  it("shares connections on Unix when the socket path is short enough, never on Windows", () => {
    const shared = buildSshArgs({ host: "h" }, "x", OPTS);
    assert.ok(shared.includes("ControlMaster=auto") && shared.includes(`ControlPersist=${CONTROL_PERSIST_SECONDS}`));
    assert.ok(CONTROL_PERSIST_SECONDS <= 15, "a revoked key stops working soon after the last call");
    assert.ok(shared.includes(`ControlPath=/tmp/s/cm/${socketKeyOf({ host: "h" })}/%C`));
    assert.ok(!buildSshArgs({ host: "h" }, "x", { ...OPTS, platform: "win32" }).includes("ControlMaster=auto"));
    const long = "/tmp/" + "d".repeat(80);
    assert.ok(!controlPathFits(long));
    assert.ok(!buildSshArgs({ host: "h" }, "x", { stateDir: long, platform: "linux" }).includes("ControlMaster=auto"));
    assert.ok(controlPathFits("/tmp/short"));
  });
  it("does without connection sharing when the state directory holds characters ssh would expand or split on", () => {
    for (const stateDir of ["/tmp/a%b", "/tmp/a b", "/tmp/a,b", "/tmp/a'b", "/tmp/a$b", "/tmp/a\nb", "/tmp/a=b"]) {
      const args = buildSshArgs({ host: "h" }, "x", { stateDir, platform: "linux" });
      assert.ok(!args.includes("ControlMaster=auto"), JSON.stringify(stateDir));
      assert.ok(!args.some((a) => a.startsWith("ControlPath")), JSON.stringify(stateDir));
    }
  });
  it("two logins never share a socket: the key follows the alias, user, port, identity and configuration file", () => {
    const base = { host: "srv", user: "deploy", port: 22, identityFile: "/keys/a", configFile: "/cfg/a" };
    const key = socketKeyOf(base);
    assert.match(key, /^[0-9a-f]{12}$/);
    assert.equal(socketKeyOf({ ...base }), key, "the same login, the same socket");
    for (const other of [{ host: "srv2" }, { user: "root" }, { port: 2222 }, { identityFile: "/keys/b" }, { configFile: "/cfg/b" }]) {
      assert.notEqual(socketKeyOf({ ...base, ...other }), key, JSON.stringify(other));
    }
    assert.notEqual(socketKeyOf({ host: "srv" }), socketKeyOf({ host: "srv", user: "srv" }), "absent is not a value");
    // the situation of the review: two aliases for one machine and one account, behind different keys
    const read = buildSshArgs({ host: "srv-read", identityFile: "/keys/read" }, "x", OPTS).find((a) => a.startsWith("ControlPath"));
    const write = buildSshArgs({ host: "srv-write", identityFile: "/keys/write" }, "x", OPTS).find((a) => a.startsWith("ControlPath"));
    assert.ok(read !== undefined && write !== undefined && read !== write);
    const sameAliasOtherKey = buildSshArgs({ host: "srv-read", identityFile: "/keys/other" }, "x", OPTS).find((a) => a.startsWith("ControlPath"));
    assert.notEqual(read, sameAliasOtherKey);
  });
  it("controlSocketDir is null on Windows, for long paths and for unsafe characters; multiplex:false turns sharing off", () => {
    assert.equal(controlSocketDir("/tmp/s", "linux", "abc123abc123"), "/tmp/s/cm/abc123abc123");
    assert.equal(controlSocketDir("/tmp/s", "win32", "abc123abc123"), null);
    assert.equal(controlSocketDir("/tmp/" + "d".repeat(80), "linux", "abc123abc123"), null);
    assert.equal(controlSocketDir("/tmp/a%b", "darwin", "abc123abc123"), null);
    const off = buildSshArgs({ host: "h" }, "x", { ...OPTS, multiplex: false });
    assert.ok(!off.includes("ControlMaster=auto"));
  });
});

describe("transports", () => {
  it("defaultTransports gives ssh for a remote profile, local for a local one, and a transport per configured site user", () => {
    const factory = defaultTransports("/tmp/s", "linux");
    assert.ok(factory.forProfile(makeProfile({ target: { kind: "ssh", ssh: { host: "h" } } })) instanceof SshTransport);
    assert.ok(factory.forProfile(makeProfile()) instanceof LocalTransport);
    const profile = makeProfile({ siteUserAccess: { shop: { host: "shop-alias" } } });
    assert.ok(factory.forSiteUser(profile, "shop") instanceof SshTransport);
    assert.equal(factory.forSiteUser(profile, "other"), null);
    // own properties only: nothing is inherited from Object.prototype
    for (const inherited of ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"]) assert.equal(factory.forSiteUser(profile, inherited), null, inherited);
  });
});

describe("runProcess", { skip: IS_WINDOWS }, () => {
  it("captures output, the exit status and the duration, never through a shell", async () => {
    const r = await runProcess("/bin/sh", ["-c", "echo out; echo err >&2; exit 3"], { timeoutMs: 5000 });
    assert.equal(r.stdout, "out\n");
    assert.equal(r.stderr, "err\n");
    assert.equal(r.exitCode, 3);
    assert.equal(r.timedOut, false);
    const literal = await runProcess("/bin/echo", ["$(id);`id`"], { timeoutMs: 5000 });
    assert.equal(literal.stdout, "$(id);`id`\n");
  });
  it("gives the child no stdin", async () => {
    const r = await runProcess("/bin/sh", ["-c", "cat; echo done"], { timeoutMs: 5000 });
    assert.equal(r.stdout, "done\n");
  });
  it("kills a child that outlives the timeout", async () => {
    const started = Date.now();
    const r = await runProcess("/bin/sh", ["-c", "sleep 30"], { timeoutMs: 300 });
    assert.equal(r.timedOut, true);
    assert.ok(Date.now() - started < 5000);
  });
  it("reports a program that cannot be started", async () => {
    const r = await runProcess("/nonexistent/program", [], { timeoutMs: 1000 });
    assert.ok(r.spawnError !== undefined);
    assert.equal(r.exitCode, null);
  });
  it("caps what it keeps of a flood of output and counts what it dropped", async () => {
    const r = await runProcess(process.execPath, ["-e", "process.stdout.write('x'.repeat(3*1024*1024))"], { timeoutMs: 10000 });
    assert.equal(r.stdout.length, 1024 * 1024);
    assert.equal(r.droppedBytes, 2 * 1024 * 1024);
  });
  it("killActive stops a running child", async () => {
    const pending = runProcess("/bin/sh", ["-c", "sleep 30"], { timeoutMs: 30_000 });
    await new Promise((resolve) => setTimeout(resolve, 100));
    killActive();
    const r = await pending;
    assert.notEqual(r.exitCode, 0);
  });
});

describe("through a fake ssh and a fake sudo", { skip: IS_WINDOWS }, () => {
  function rig(extraProfile: Record<string, unknown> = {}) {
    const dir = shortTmp("clps-");
    const clpctl = installSimClpctl(join(dir, "bin"));
    const log = join(dir, "ssh.log");
    const simState = join(dir, "sim.json");
    const simLog = join(dir, "sim.log");
    const profile = makeProfile({ target: { kind: "ssh", ssh: { host: "my-server" } }, elevation: "sudo", clpctlPath: clpctl, ...extraProfile } as never);
    const savedPath = process.env["PATH"];
    const savedEnv = { ...process.env };
    // The fake ssh, sudo and the node binary come first; the real ssh is never reached.
    process.env["PATH"] = `${join(SIM_DIR, "bin")}:${savedPath ?? ""}`;
    process.env["FAKE_SSH_LOG"] = log;
    process.env["CLPCTL_SIM_STATE"] = simState;
    process.env["CLPCTL_SIM_LOG"] = simLog;
    const restore = (): void => {
      process.env["PATH"] = savedPath;
      for (const key of ["FAKE_SSH_LOG", "CLPCTL_SIM_STATE", "CLPCTL_SIM_LOG", "FAKE_SSH_FAIL"]) {
        if (savedEnv[key] === undefined) delete process.env[key];
        else process.env[key] = savedEnv[key];
      }
    };
    return { dir, profile, log, simState, simLog, restore, state: (): SimState => JSON.parse(readFileSync(simState, "utf8")) as SimState };
  }

  function engineFor(r: ReturnType<typeof rig>): Engine {
    const redactor = new Redactor();
    const transports = defaultTransports(r.dir, "linux");
    return new Engine({
      profiles: [r.profile], defaultProfile: r.profile.name, catalog: buildCatalog(), transports,
      audit: new AuditLog(r.dir, redactor), redactor, secretsFor: (n) => new SecretsStore(r.dir, n),
      limiter: new RateLimiter(), tokens: new PlanTokens(), detector: new Detector(transports), serverVersion: "t",
      newPassword: () => FIXED_PASSWORD,
    });
  }

  it("runs `sudo -n <clpctl> <command> '<tokens>'` on the remote side, quoting template names with spaces", async () => {
    const r = rig();
    try {
      const engine = engineFor(r);
      const out = await engine.call("clp_site_add_php", { domainName: "shop.example.com", phpVersion: "8.4", vhostTemplate: "PrestaShop 1.7", siteUser: "shop" }, new FakeIO(approve));
      assert.equal(out.isError, false, JSON.stringify(bodyOf(out)));
      const calls = readFileSync(r.log, "utf8").trim().split("\n");
      const add = calls.find((c) => c.includes("site:add:php")) as string;
      assert.match(add, /^my-server\tsudo -n \/tmp\/clps-[^ ]+\/bin\/clpctl site:add:php '--domainName=shop\.example\.com' '--phpVersion=8\.4' '--vhostTemplate=PrestaShop 1\.7' '--siteUser=shop' '--siteUserPassword=[A-Za-z0-9]{32}'$/);
      assert.equal(r.state().sites[0]?.template, "PrestaShop 1.7");
      assert.equal(r.state().sites[0]?.password, FIXED_PASSWORD);
      // the probe went through the same path
      assert.ok(calls.some((c) => /sudo -n \/tmp\/clps-[^ ]+\/bin\/clpctl$/.test(c)));
    } finally {
      r.restore();
    }
  });

  it("without sudo (elevation none) the remote command has no sudo", async () => {
    const r = rig({ elevation: "none" });
    try {
      await engineFor(r).call("clp_user_list", {}, new FakeIO(undefined, { canElicitForm: false }));
      assert.ok(readFileSync(r.log, "utf8").split("\n").filter(Boolean).every((c) => !c.includes("sudo")));
    } finally {
      r.restore();
    }
  });

  it("reports an unreachable host as a failure with the ssh message, and nothing was applied", async () => {
    const r = rig();
    try {
      process.env["FAKE_SSH_FAIL"] = "1";
      const out = await engineFor(r).call("clp_site_add_static", { domainName: "a.example.com", siteUser: "abc" }, new FakeIO(approve));
      assert.equal(out.isError, true);
      assert.equal(bodyOf(out).exitCode, 255);
      assert.match(bodyOf(out).output.stderr, /Connection refused/);
      assert.ok(!existsSync(r.simState) || r.state().sites.length === 0);
    } finally {
      r.restore();
    }
  });

  it("site-user tools log in as that user, with no sudo and the user's own alias", async () => {
    const r = rig({ siteUserAccess: { shop: { host: "shop-alias" } } });
    try {
      process.env["CLPCTL_SIM_AS"] = "shop";
      const out = await engineFor(r).call("clp_system_permissions_reset", { siteUser: "shop", path: "htdocs/www.example.com" }, new FakeIO(approve));
      assert.equal(out.isError, false, JSON.stringify(bodyOf(out)));
      const line = readFileSync(r.log, "utf8").trim().split("\n").pop() as string;
      assert.match(line, /^shop-alias\t\/tmp\/clps-[^ ]+\/bin\/clpctl system:permissions:reset '--directories=770' '--files=660' '--path=htdocs\/www\.example\.com'$/);
      assert.ok(!line.includes("sudo"));
    } finally {
      delete process.env["CLPCTL_SIM_AS"];
      r.restore();
    }
  });

  it("a program path that exists nowhere is reported, not hidden", async () => {
    const r = rig({ clpctlPath: "/nonexistent/clpctl" });
    try {
      const out = await engineFor(r).call("clp_user_list", {}, new FakeIO(undefined, { canElicitForm: false }));
      assert.equal(out.isError, true);
    } finally {
      r.restore();
    }
  });
});

describe("a hanging ssh", { skip: IS_WINDOWS }, () => {
  it("is killed at the timeout and the result says so", async () => {
    const dir = shortTmp("clph-");
    writeExecutable(join(dir, "bin"), "ssh", "#!/bin/sh\nsleep 30\n");
    const saved = process.env["PATH"];
    process.env["PATH"] = `${join(dir, "bin")}:${saved ?? ""}`;
    try {
      const transport = new SshTransport({ host: "h" }, { stateDir: dir, platform: "linux" });
      const started = Date.now();
      const r = await transport.run({ argv: ["/usr/bin/clpctl"], fixedWords: 1, timeoutMs: 400 });
      assert.equal(r.timedOut, true);
      assert.ok(Date.now() - started < 6000);
    } finally {
      process.env["PATH"] = saved;
    }
  });
});

describe("the connection-sharing directory", { skip: IS_WINDOWS }, () => {
  function fakeSsh(): { dir: string; log: string; restore: () => void } {
    const dir = shortTmp("clpm-");
    const log = join(dir, "args.log");
    writeExecutable(join(dir, "bin"), "ssh", `#!/bin/sh\nprintf '%s\\n' "$@" > "${log}"\n`);
    const saved = process.env["PATH"];
    process.env["PATH"] = `${join(dir, "bin")}:${saved ?? ""}`;
    return { dir, log, restore: () => { process.env["PATH"] = saved; } };
  }

  it("is created privately before the first run, and ssh is told to use it", async () => {
    const rig = fakeSsh();
    try {
      const stateDir = join(rig.dir, "state");
      const transport = new SshTransport({ host: "h" }, { stateDir, platform: "linux" });
      const r = await transport.run({ argv: ["/usr/bin/clpctl"], fixedWords: 1, timeoutMs: 5000 });
      assert.equal(r.exitCode, 0);
      const dir = join(stateDir, "cm", socketKeyOf({ host: "h" }));
      assert.equal(statSync(join(stateDir, "cm")).mode & 0o777, 0o700);
      assert.equal(statSync(dir).mode & 0o777, 0o700);
      const args = readFileSync(rig.log, "utf8").split("\n");
      assert.ok(args.includes("ControlMaster=auto"));
      assert.ok(args.includes(`ControlPath=${dir}/%C`));
    } finally {
      rig.restore();
    }
  });

  it("a replaced key file gets a new connection: the file's stamp is part of the socket key", async () => {
    const rig = fakeSsh();
    try {
      const key = join(rig.dir, "id_test");
      writeFileSync(key, "one");
      const stateDir = join(rig.dir, "state");
      const transport = new SshTransport({ host: "h", identityFile: key }, { stateDir, platform: "linux" });
      const controlPath = async (): Promise<string> => {
        const r = await transport.run({ argv: ["/usr/bin/clpctl"], fixedWords: 1, timeoutMs: 5000 });
        assert.equal(r.exitCode, 0);
        return readFileSync(rig.log, "utf8").split("\n").find((a) => a.startsWith("ControlPath=")) as string;
      };
      const first = await controlPath();
      assert.equal(await controlPath(), first, "the same key file, the same connection");
      writeFileSync(key, "a replacement of another size");
      const second = await controlPath();
      assert.notEqual(second, first, "a replaced key file does not reuse the old connection");
      rmSync(key);
      const third = await controlPath(); // an unreadable key file still gives a working command line
      assert.notEqual(third, second);
      for (const path of [first, second, third]) assert.equal(statSync(path.slice("ControlPath=".length, -"/%C".length)).mode & 0o777, 0o700);
    } finally {
      rig.restore();
    }
  });

  it("is given up on when it cannot be made private: the command still runs, without sharing", async () => {
    const rig = fakeSsh();
    try {
      const stateDir = join(rig.dir, "state");
      mkdirSync(stateDir);
      writeFileSync(join(stateDir, "cm"), "a file in the way");
      const transport = new SshTransport({ host: "h" }, { stateDir, platform: "linux" });
      const r = await transport.run({ argv: ["/usr/bin/clpctl"], fixedWords: 1, timeoutMs: 5000 });
      assert.equal(r.exitCode, 0);
      const args = readFileSync(rig.log, "utf8").split("\n");
      assert.ok(!args.includes("ControlMaster=auto"));
      assert.ok(!args.some((a) => a.startsWith("ControlPath")));
    } finally {
      rig.restore();
    }
  });
});
