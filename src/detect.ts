import type { Profile } from "./config/types.ts";
import type { ToolSpec } from "./catalog/define.ts";
import { buildArgv } from "./exec/quote.ts";
import { parseUsageListing, sanitize } from "./exec/output.ts";
import type { TransportFactory } from "./exec/transport.ts";

export type DetectStatus = "ok" | "unparsed" | "failed";

export interface Detection {
  readonly status: DetectStatus;
  /** command -> options its usage line shows */
  readonly commands: ReadonlyMap<string, ReadonlySet<string>>;
  readonly at: number;
  readonly detail?: string;
}

export type Availability =
  | { readonly available: true; readonly known: boolean }
  | { readonly available: false; readonly reason: string };

const OK_TTL_MS = 60 * 60_000;
const FAIL_TTL_MS = 20_000;
const PROBE_TIMEOUT_MS = 30_000;
/** A forced re-detection (refresh) within this time of the last probe answers from the cache: each probe is an ssh session and a clpctl run on the host. */
const REFRESH_MIN_MS = 30_000;

/**
 * Feature detection (docs/adr/0004): run `clpctl` with no arguments once per profile and parse the
 * usage listing. Cached in memory; a failed probe is retried soon.
 */
export class Detector {
  private readonly cache = new Map<string, Promise<Detection>>();
  private readonly transports: TransportFactory;
  private readonly now: () => number;

  constructor(transports: TransportFactory, now: () => number = Date.now) {
    this.transports = transports;
    this.now = now;
  }

  get(profile: Profile, refresh = false): Promise<Detection> {
    const cached = this.cache.get(profile.name);
    if (cached !== undefined) {
      return cached.then((detection) => {
        const age = this.now() - detection.at;
        const ttl = detection.status === "ok" ? OK_TTL_MS : FAIL_TTL_MS;
        if (age < ttl && (!refresh || age < REFRESH_MIN_MS)) return detection;
        // callers that arrive together all find the old detection: the first one probes, the others take its probe
        const newer = this.cache.get(profile.name);
        if (newer !== undefined && newer !== cached) return newer;
        return this.probe(profile);
      });
    }
    return this.probe(profile);
  }

  private probe(profile: Profile): Promise<Detection> {
    const promise = this.run(profile);
    this.cache.set(profile.name, promise);
    return promise;
  }

  private async run(profile: Profile): Promise<Detection> {
    const at = this.now();
    const prefix = profile.elevation === "sudo" ? ["sudo", "-n"] : [];
    const argv = buildArgv({ prefix, clpctlPath: profile.clpctlPath, tokens: [] });
    try {
      const result = await this.transports.forProfile(profile).run({
        argv,
        fixedWords: argv.length,
        timeoutMs: Math.min(profile.timeouts.defaultMs, PROBE_TIMEOUT_MS),
      });
      const listing = parseUsageListing(result.stdout);
      if (listing.length > 0) {
        return {
          status: "ok",
          commands: new Map(listing.map((c) => [c.name, new Set(c.options)])),
          at,
        };
      }
      if (result.spawnError !== undefined || result.timedOut || result.exitCode !== 0) {
        const why = result.timedOut
          ? "the probe timed out"
          : result.spawnError !== undefined
            ? `could not start the transport: ${sanitize(result.spawnError).slice(0, 120)}`
            : `the probe exited with status ${String(result.exitCode)}`;
        return { status: "failed", commands: new Map(), at, detail: why };
      }
      return { status: "unparsed", commands: new Map(), at, detail: "clpctl printed no recognisable usage listing" };
    } catch (error) {
      return {
        status: "failed",
        commands: new Map(),
        at,
        detail: error instanceof Error ? sanitize(error.message).slice(0, 120) : "probe failed",
      };
    }
  }
}

/** Is the tool usable with what the server's clpctl lists? Unknown detection never blocks. */
export function availabilityOf(detection: Detection, spec: ToolSpec): Availability {
  if (spec.kind !== "clpctl" || spec.command === null) return { available: true, known: false };
  if (detection.status !== "ok") return { available: true, known: false };
  const options = detection.commands.get(spec.command);
  if (options === undefined) {
    return {
      available: false,
      reason: `this server's clpctl does not list the command ${spec.command} (an older or different CloudPanel version?). Run clp_list_commands to see what it has`,
    };
  }
  for (const [name, option] of Object.entries(spec.options)) {
    if (option.required && !options.has(name)) {
      return {
        available: false,
        reason: `this server's clpctl lists ${spec.command} without the option --${name} that this tool needs (a different CloudPanel version?). Run clp_list_commands to compare`,
      };
    }
  }
  return { available: true, known: true };
}
