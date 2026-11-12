import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditLog, type AuditEntry } from "../src/audit.ts";
import { buildCatalog } from "../src/catalog/index.ts";
import type { ToolSpec } from "../src/catalog/define.ts";
import { DEFAULT_RATE_LIMITS } from "../src/config/load.ts";
import type { Profile } from "../src/config/types.ts";
import { DEFAULT_APP_PORTS } from "../src/validate/patterns.ts";
import { Detector } from "../src/detect.ts";
import { Engine, NeedInput, type ClientIO, type Outcome } from "../src/engine.ts";
import type { RunResult } from "../src/exec/process.ts";
import type { RunRequest, Transport, TransportFactory } from "../src/exec/transport.ts";
import type { ApprovalRequest, HumanDecision } from "../src/policy/approval.ts";
import { RateLimiter } from "../src/policy/rate.ts";
import { PlanTokens } from "../src/policy/tokens.ts";
import { Redactor } from "../src/secrets/redact.ts";
import { SecretsStore } from "../src/secrets/store.ts";
import { ClpctlSim, initialState, type SimOptions, type SimState } from "./sim/clpctl.ts";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const SIM_DIR = join(ROOT, "test", "sim");
export const DIST_ENTRY = join(ROOT, "dist", "index.js");
export const IS_WINDOWS = process.platform === "win32";

/** A fixed 32-character password for tests that need to know the generated value. */
export const FIXED_PASSWORD = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";

const cleanup: string[] = [];
// "exit" also runs under --test-force-exit, which skips the root `after` hooks.
process.on("exit", () => {
  for (const dir of cleanup) rmSync(dir, { recursive: true, force: true });
});

/** A temporary directory with a SHORT path (ssh control sockets are limited to 104 bytes). */
export function shortTmp(prefix = "clpt-"): string {
  const base = existsSync("/tmp") ? "/tmp" : tmpdir();
  const dir = mkdtempSync(join(base, prefix));
  cleanup.push(dir);
  return dir;
}

export function makeProfile(over: Partial<Profile> = {}): Profile {
  return Object.freeze({
    name: "test",
    target: { kind: "local" },
    elevation: "none",
    clpctlPath: "/usr/bin/clpctl",
    allow: new Set(["write", "destructive", "admin"]),
    approvalWrite: "ask",
    protect: { domains: [], siteUsers: [], databases: [], panelUsers: [] },
    fileDirs: ["/var/lib/cloudpanel-mcp-server"],
    allowUntrustedFileDirs: false,
    proxyHosts: ["127.0.0.1", "localhost", "::1"],
    appPorts: DEFAULT_APP_PORTS,
    siteUserAccess: {},
    inventory: { enabled: false, command: "/usr/local/sbin/cloudpanel-mcp-inventory" },
    rateLimits: DEFAULT_RATE_LIMITS,
    timeouts: { defaultMs: 120_000, letsEncryptMs: 600_000, dbMs: 600_000 },
    ...over,
  } as Profile);
}

export interface RecordedRun { readonly argv: readonly string[]; readonly fixedWords: number; readonly timeoutMs: number }

/** Runs requests against the in-process simulator. It sees the argv exactly as a real transport would. */
export class SimTransport implements Transport {
  readonly label = "sim";
  readonly calls: RecordedRun[] = [];
  readonly sim: ClpctlSim;
  /** Replaces the result of the next run(s), to simulate failures. */
  override: ((request: RunRequest) => RunResult | undefined) | undefined;

  constructor(state: SimState = initialState(), options: SimOptions = {}) {
    this.sim = new ClpctlSim(state, options);
  }

  get state(): SimState {
    return this.sim.state;
  }

  async run(request: RunRequest): Promise<RunResult> {
    this.calls.push({ argv: request.argv, fixedWords: request.fixedWords, timeoutMs: request.timeoutMs });
    const forced = this.override?.(request);
    if (forced !== undefined) return forced;
    const words = [...request.argv];
    if (words[0] === "sudo") words.splice(0, 2);
    words.shift(); // the clpctl path
    const out = this.sim.run(words);
    return { exitCode: out.exitCode, signal: null, timedOut: false, stdout: out.stdout, stderr: out.stderr, droppedBytes: 0, durationMs: 1 };
  }
}

export function okResult(over: Partial<RunResult> = {}): RunResult {
  return { exitCode: 0, signal: null, timedOut: false, stdout: "", stderr: "", droppedBytes: 0, durationMs: 1, ...over };
}

export type Answer = HumanDecision | ((request: ApprovalRequest) => HumanDecision);

/** A scripted human. Records every question asked. */
export class FakeIO implements ClientIO {
  readonly asked: ApprovalRequest[] = [];
  canElicitForm: boolean;
  /** Modern era: a re-run with the answer is not a new question. */
  readonly replaysAnswers: boolean;
  private readonly answer: Answer | undefined;
  /** Modern era: the first entry has no answer yet and the engine must get NeedInput. */
  private readonly modernFirstEntry: boolean;

  constructor(answer: Answer | undefined, options: { canElicitForm?: boolean; modernFirstEntry?: boolean; replaysAnswers?: boolean } = {}) {
    this.answer = answer;
    this.replaysAnswers = options.replaysAnswers ?? false;
    this.canElicitForm = options.canElicitForm ?? true;
    this.modernFirstEntry = options.modernFirstEntry ?? false;
  }

  async ask(request: ApprovalRequest): Promise<HumanDecision> {
    this.asked.push(request);
    if (this.modernFirstEntry || this.answer === undefined) throw new NeedInput(request);
    return typeof this.answer === "function" ? this.answer(request) : this.answer;
  }

  /** 2026 era: the answer the client holds for any question (a constant), or none. */
  answerFor(_key: string): HumanDecision | undefined {
    if (this.modernFirstEntry || this.answer === undefined) return undefined;
    if (typeof this.answer === "function") throw new Error("a FakeIO of the 2026 era needs a constant answer");
    return this.answer;
  }
}

/** Types the target's name exactly (destructive/admin) or ticks the box (write). */
export const approve: Answer = (request) =>
  request.kind === "type-target"
    ? { action: "accept", content: { typed: request.target } }
    : { action: "accept", content: { approve: true } };

export const noHuman = new FakeIO(undefined, { canElicitForm: false });

export interface Harness {
  readonly engine: Engine;
  readonly transport: SimTransport;
  readonly stateDir: string;
  readonly auditPath: string;
  readonly profile: Profile;
  readonly redactor: Redactor;
  readonly tokens: PlanTokens;
  readonly audit: () => Record<string, unknown>[];
  /** call a tool; planFirst runs a dry run to get the token and applies with it */
  readonly call: (name: string, args: Record<string, unknown>, io: ClientIO) => Promise<Outcome>;
  readonly apply: (name: string, args: Record<string, unknown>, io: ClientIO) => Promise<Outcome>;
}

export function makeHarness(options: { profile?: Partial<Profile>; profiles?: Profile[]; transport?: SimTransport; password?: () => string; now?: () => number; catalog?: ToolSpec[]; failAudit?: (entry: AuditEntry) => boolean } = {}): Harness {
  const stateDir = shortTmp();
  const profiles = options.profiles ?? [makeProfile(options.profile)];
  const profile = profiles[0] as Profile;
  const transport = options.transport ?? new SimTransport();
  const factory: TransportFactory = { forProfile: () => transport, forSiteUser: (p, user) => (Object.hasOwn(p.siteUserAccess, user) ? transport : null) };
  const redactor = new Redactor();
  const audit = new AuditLog(stateDir, redactor);
  if (options.failAudit !== undefined) {
    // a log that works except for the records the test chooses: "disk full" for exactly those
    const record = audit.record.bind(audit);
    const fails = options.failAudit;
    audit.record = (entry: AuditEntry): void => {
      if (fails(entry)) throw new Error("disk full");
      record(entry);
    };
  }
  const tokens = new PlanTokens(options.now === undefined ? {} : { now: options.now });
  const engine = new Engine({
    profiles,
    defaultProfile: profiles.length === 1 ? profile.name : "",
    catalog: options.catalog ?? buildCatalog(),
    transports: factory,
    audit,
    redactor,
    secretsFor: (name) => new SecretsStore(stateDir, name),
    limiter: new RateLimiter(options.now),
    tokens,
    detector: new Detector(factory, options.now),
    serverVersion: "0.0.0-test",
    newPassword: options.password ?? (() => FIXED_PASSWORD),
    ...(options.now === undefined ? {} : { now: options.now }),
  });
  const auditPath = join(stateDir, "audit.jsonl");
  const readAudit = (): Record<string, unknown>[] =>
    existsSync(auditPath)
      ? readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>)
      : [];
  const call = (name: string, args: Record<string, unknown>, io: ClientIO): Promise<Outcome> => engine.call(name, args, io);
  const apply = async (name: string, args: Record<string, unknown>, io: ClientIO): Promise<Outcome> => {
    const plan = await engine.call(name, { ...args, dryRun: true }, io);
    const token = plan.body["planToken"];
    if (typeof token !== "string") return plan;
    return engine.call(name, { ...args, planToken: token }, io);
  };
  return { engine, transport, stateDir, auditPath, profile, redactor, tokens, audit: readAudit, call, apply };
}

/** Writes an executable wrapper in a temp dir and returns its path (a clean path for clpctlPath). */
export function writeExecutable(dir: string, name: string, body: string): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  writeFileSync(path, body);
  chmodSync(path, 0o755);
  return path;
}

/** A `clpctl` executable that runs the simulator. */
export function installSimClpctl(dir: string): string {
  return writeExecutable(dir, "clpctl", `#!/bin/sh\nexec "${process.execPath}" "${join(SIM_DIR, "cli.ts")}" "$@"\n`);
}

export function bodyOf(outcome: Outcome): Record<string, any> {
  return outcome.body as Record<string, any>;
}
