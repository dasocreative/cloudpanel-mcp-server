#!/usr/bin/env node
/**
 * Mutation check for the guards. Each mutant breaks ONE guard (a gate, a pattern, a check, a
 * redaction, a mode bit) in a throw-away copy of the repository and runs the tests that are meant to
 * notice. A mutant that no test notices "survives" and the script fails: either the guard is not
 * tested, or the test is too weak.
 *
 *   npm run mutation                 run every mutant (a few minutes)
 *   npm run mutation -- --list       list the mutants
 *   npm run mutation -- --check      only check that the code each mutant changes still exists (seconds)
 *   npm run mutation -- --only a,b   run some mutants
 *   npm run mutation -- --jobs 8     parallel workers (default 4)
 *
 * It needs no build: the tests run on the TypeScript sources through Node's type stripping.
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COPY = ["src", "test", "scripts", "hardening", "inventory", "docs", "package.json", "tsconfig.json", "tsconfig.test.json"];

const HARDENING = ["test/hardening.test.ts", "test/protection.test.ts"];
const UNIT = ["test/engine.test.ts", "test/catalog.test.ts", "test/patterns.test.ts", "test/config.test.ts", "test/output.test.ts", "test/policy.test.ts", "test/secrets.test.ts", "test/mcp-io.test.ts", "test/quote.test.ts", "test/fsutil.test.ts", ...HARDENING];
const ENGINE = ["test/engine.test.ts", "test/mcp-io.test.ts", ...HARDENING];
const GATE = ["test/gate.test.ts"];
const INVENTORY = ["test/inventory.test.ts"];

/** [find, replace] pairs; every `find` must occur in the file or the mutant is reported as broken. */
const MUTANTS = [
  // ------------------------------------------------------------------ engine: the pipeline
  { id: "engine-class-gate", file: "src/engine.ts", edits: [['if (spec.cls !== "read" && !profile.allow.has(spec.cls as "write" | "destructive" | "admin")) {', "if (false) {"]], tests: ENGINE },
  { id: "engine-password-key-scan", file: "src/engine.ts", edits: [["else if (hasPasswordKey(rawArgs)) early =", "else if (false) early ="]], tests: ENGINE },
  { id: "engine-protected-targets", file: "src/engine.ts", edits: [["if (why !== null) return this.refuse(spec.name, spec.cls, profile, why);", ""]], tests: ENGINE },
  { id: "engine-availability", file: "src/engine.ts", edits: [["if (!availability.available) return this.refuse(spec.name, spec.cls, profile, availability.reason);", ""]], tests: ENGINE },
  { id: "engine-plan-typing-guard", file: "src/engine.ts", edits: [["if (untyped !== null) return this.refuse(spec.name, spec.cls, profile, `internal error: ${untyped}`);", ""]], tests: ENGINE },
  { id: "engine-token-not-required", file: "src/engine.ts", edits: [['const needsToken = cls !== "write";', "const needsToken = false;"]], tests: ENGINE },
  { id: "engine-dry-run-runs", file: "src/engine.ts", edits: [["if (dryRun || (needsToken && planToken === undefined)) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-token-not-verified", file: "src/engine.ts", edits: [["if (!verdict.ok) return this.refuse(spec.name, cls, profile, verdict.reason);", ""]], tests: ENGINE },
  { id: "engine-token-reusable", file: "src/engine.ts", edits: [["if (nonce !== undefined && !this.d.tokens.consume(nonce)) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-rate-limit-check", file: "src/engine.ts", edits: [["if (!peek.ok) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-rate-limit-take", file: "src/engine.ts", edits: [["const taken = this.d.limiter.take(limitKey, limit);", "const taken = { ok: true as const };"]], tests: ENGINE },
  { id: "engine-approval-skipped", file: "src/engine.ts", edits: [['if (cls !== "write" || profile.approvalWrite === "ask") {', "if (false) {"]], tests: ENGINE },
  { id: "engine-approval-verdict-ignored", file: "src/engine.ts", edits: [["if (!verdict.approved) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-unsupported-client-runs", file: "src/engine.ts", edits: [["if (!io.canElicitForm) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-audit-failure-ignored", file: "src/engine.ts", edits: [["if (failure !== null) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-output-not-scrubbed", file: "src/engine.ts", edits: [["const clean = (text: string): string => truncate(sanitize(redactor.scrub(text)));", "const clean = (text: string): string => truncate(sanitize(text));"]], tests: ENGINE },
  { id: "engine-error-line-with-exit-0", file: "src/engine.ts", edits: [["const sawErrorLine = exitOk && logLine?.severe === true;", "const sawErrorLine = false;"]], tests: ENGINE },
  { id: "engine-failed-password-file-kept", file: "src/engine.ts", edits: [["secretsFile = reservation.commit(ok);", "secretsFile = reservation.commit(true);"]], tests: ENGINE },
  { id: "engine-secret-output-shown", file: "src/engine.ts", edits: [["const hideOutput = plan.captureToFile === true;", "const hideOutput = false;"]], tests: ENGINE },
  { id: "engine-secret-output-shown-when-saving-fails", file: "src/engine.ts", edits: [["const hide = extra.hideOutput === true;", "const hide = extra.hideOutput === true && extra.captured === true;"]], tests: ENGINE },
  { id: "engine-secret-stderr-shown", file: "src/engine.ts", edits: [["stderr: hide ? HIDDEN : clean(result.stderr),", "stderr: clean(result.stderr),"]], tests: ENGINE },
  { id: "engine-secret-server-message-shown", file: "src/engine.ts", edits: [["if (!hide && !ok && extra.logLine !== null", "if (!ok && extra.logLine !== null"]], tests: ENGINE },
  { id: "engine-arguments-size-unbounded", file: "src/engine.ts", edits: [["if (argumentsTooLarge(rawArgs)) early =", "if (false) early ="]], tests: ENGINE },
  { id: "engine-approval-key-ignores-the-plan-token", file: "src/engine.ts", edits: [['`${binding}\\n${nonce ?? ""}`', "binding"]], tests: ENGINE },
  { id: "engine-approvals-in-parallel", file: "src/engine.ts", edits: [["if (this.pendingApprovals.has(profile.name)) return { refused: busy };", "if (false) return { refused: busy };"]], tests: ENGINE },
  { id: "engine-ask-limit-not-checked", file: "src/engine.ts", edits: [["if (!room.ok) return { refused: tooMany(room.retryAfterSeconds) };", ""]], tests: ENGINE },
  { id: "engine-ask-limit-not-counted", file: "src/engine.ts", edits: [["this.d.limiter.take(key, limit);\n      return { decision, tokenProblem: useToken() };", "return { decision, tokenProblem: useToken() };"]], tests: ENGINE },
  { id: "engine-approval-audit-failure-ignored", file: "src/engine.ts", edits: [["if (auditWarning !== null) {\n        return this.refuse(spec.name, cls, profile, `${auditWarning}, so nothing is run`);\n      }\n    } else {", "} else {"]], tests: ENGINE },
  { id: "engine-approval-audit-failure-ignored-client-writes", file: "src/engine.ts", edits: [["      if (auditWarning !== null) {\n        return this.refuse(spec.name, cls, profile, `${auditWarning}, so nothing is run`);\n      }\n    }\n\n    const taken", "    }\n\n    const taken"]], tests: ENGINE },
  { id: "engine-inventory-not-gated", file: "src/engine.ts", edits: [["if (!profile.inventory.enabled) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-tools-visible-without-class", file: "src/engine.ts", edits: [["return profiles.some((p) => p.allow.has(spec.cls as \"write\" | \"destructive\" | \"admin\"));", "return true;"]], tests: ENGINE },
  { id: "engine-detector-ignored", file: "src/detect.ts", edits: [["if (option.required && !options.has(name)) {", "if (false) {"]], tests: ENGINE },
  { id: "detect-command-missing-ignored", file: "src/detect.ts", edits: [["if (options === undefined) {", "if (false) {"]], tests: ENGINE },

  // ------------------------------------------------------------------ approval, tokens, rate, protect
  { id: "engine-question-open-ignored", file: "src/engine.ts", edits: [["if (live && open.id !== request.key) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-question-answer-reusable", file: "src/engine.ts", edits: [["this.openQuestions.delete(profile.name); // claimed: an answer is used once", ""]], tests: ENGINE },
  { id: "engine-question-not-charged", file: "src/engine.ts", edits: [["      const taken = this.d.limiter.take(key, limit);\n      if (!taken.ok) return { refused: tooMany(taken.retryAfterSeconds) };\n      if (!live) {", "      const taken = { ok: true as const };\n      if (!live) {"]], tests: ENGINE },
  { id: "engine-question-repeats-free", file: "src/engine.ts", edits: [["      const taken = this.d.limiter.take(key, limit);\n      if (!taken.ok) return { refused: tooMany(taken.retryAfterSeconds) };\n      if (!live) {", "      const taken = live ? { ok: true as const } : this.d.limiter.take(key, limit);\n      if (!taken.ok) return { refused: tooMany(taken.retryAfterSeconds) };\n      if (!live) {"]], tests: ENGINE },
  { id: "engine-question-outlives-the-token", file: "src/engine.ts", edits: [["Math.min(now + QUESTION_TTL_MS, deadline ?? Number.POSITIVE_INFINITY)", "now + QUESTION_TTL_MS"]], tests: ENGINE },
  { id: "engine-question-without-nonce", file: "src/engine.ts", edits: [["{ ...request, key: `${request.key}-${question.nonce}` }", "request"]], tests: ENGINE },
  { id: "engine-question-never-lapses", file: "src/engine.ts", edits: [["const live = open !== undefined && open.until > now;", "const live = open !== undefined;"]], tests: ENGINE },
  { id: "engine-question-not-audited", file: "src/engine.ts", edits: [["        onNewQuestion();\n", ""]], tests: ENGINE },
  { id: "engine-server-message-not-rescrubbed", file: "src/engine.ts", edits: [["extractServerMessage([result.stdout, result.stderr], (text) => redactor.scrub(text))", "extractServerMessage([result.stdout, result.stderr])"]], tests: ENGINE },
  { id: "engine-inventory-cut-before-scrub", file: "src/engine.ts", edits: [["this.d.redactor.scrub(text).slice(0, 300)", "this.d.redactor.scrub(text.slice(0, 600)).slice(0, 300)"]], tests: ENGINE },
  { id: "engine-token-not-rechecked", file: "src/engine.ts", edits: [["if (!again.ok) return again.reason;", ""]], tests: ENGINE },
  { id: "engine-reads-ungated", file: "src/engine.ts", edits: [["return this.readGateFor(profile).run(() => this.execute(spec, plan, profile, transport));", "return this.execute(spec, plan, profile, transport);"]], tests: ENGINE },
  { id: "engine-reads-not-audited", file: "src/engine.ts", edits: [['    this.record({\n      event: "end",', '    if (spec.cls !== "read") this.record({\n      event: "end",']], tests: ENGINE },
  { id: "engine-unknown-tool-name-raw", file: "src/engine.ts", edits: [["this.refuse(this.clean(name, 80), undefined, undefined, \"unknown tool\")", "this.refuse(name.slice(0, 80), undefined, undefined, \"unknown tool\")"]], tests: ENGINE },
  { id: "engine-inventory-unbounded", file: "src/engine.ts", edits: [["if (size > MAX_INVENTORY_CHARS) {", "if (false) {"]], tests: ENGINE },
  { id: "engine-listing-unbounded", file: "src/engine.ts", edits: [["const commands = capped(serverCommands, 300);", "const commands = capped(serverCommands, 3_000_000);"]], tests: ENGINE },
  { id: "detector-refresh-always-probes", file: "src/detect.ts", edits: [["if (age < ttl && (!refresh || age < REFRESH_MIN_MS)) return detection;", "if (age < ttl && !refresh) return detection;"]], tests: ENGINE },
  { id: "detector-concurrent-probes", file: "src/detect.ts", edits: [["        if (newer !== undefined && newer !== cached) return newer;\n", ""]], tests: ENGINE },
  { id: "semaphore-unbounded", file: "src/mutex.ts", edits: [["if (this.active >= this.max) {", "if (false) {"]], tests: [...ENGINE, "test/mutex.test.ts"] },
  { id: "semaphore-barging", file: "src/mutex.ts", edits: [["      if (next !== undefined) next();\n      else this.active -= 1;", "      this.active -= 1;\n      next?.();"]], tests: ["test/mutex.test.ts"] },
  { id: "semaphore-waiters-never-woken", file: "src/mutex.ts", edits: [["if (next !== undefined) next();", "if (next !== undefined) void 0;"]], tests: ["test/mutex.test.ts"] },
  { id: "tokens-consumed-unbounded", file: "src/policy/tokens.ts", edits: [["while (this.consumed.size > MAX_CONSUMED) {", "while (false) {"]], tests: UNIT },
  { id: "tokens-consumed-dropped-too-soon", file: "src/policy/tokens.ts", edits: [["if (oldest === undefined) break;\n      this.consumed.delete(oldest);", "if (oldest === undefined) break;\n      this.consumed.clear();"]], tests: UNIT },
  { id: "audit-no-throttle", file: "src/audit.ts", edits: [["if (kind !== null && !this.admit(kind, minute)) return;", ""]], tests: ["test/secrets.test.ts"] },
  { id: "audit-throttle-spares-reads", file: "src/audit.ts", edits: [['if (cls === "read") return `${entry.event}:read`;', ""]], tests: ["test/secrets.test.ts"] },
  { id: "audit-refusal-kinds-merged", file: "src/audit.ts", edits: [["return `refused:${cls}:${reasonKind(entry.reason)}`;", "return `refused:${cls}`;"]], tests: ["test/secrets.test.ts"] },
  { id: "audit-unsupported-approvals-unthrottled", file: "src/audit.ts", edits: [['if (entry.event === "approval" && entry.decision === "unsupported") return `approval:${cls}:unsupported`;', ""]], tests: ["test/secrets.test.ts"] },
  { id: "audit-reason-kind-protected", file: "src/audit.ts", edits: [['if (/ is protected in |cannot be changed through this server/.test(r)) return "protected";', ""]], tests: ["test/secrets.test.ts"] },
  { id: "audit-reason-kind-token", file: "src/audit.ts", edits: [['if (r.includes("plantoken")) return "token";', ""]], tests: ["test/secrets.test.ts"] },
  { id: "audit-throttle-never-resets", file: "src/audit.ts", edits: [["if (window.minute === minute && !all) continue;", "if (!all) continue;"]], tests: ["test/secrets.test.ts"] },
  { id: "audit-throttle-holds-back-changes", file: "src/audit.ts", edits: [['    if (entry.event === "plan") return `plan:${cls}`;', '    if (entry.event === "plan") return `plan:${cls}`;\n    if (entry.event === "start" || entry.event === "approval") return `${entry.event}:${cls}`;']], tests: ["test/secrets.test.ts"] },
  { id: "user-delete-without-force", file: "src/catalog/tools/users.ts", edits: [['(exit status 0)\n      flags: ["--force"],', '(exit status 0)\n      flags: [],']], tests: [...ENGINE, "test/catalog.test.ts"] },
  { id: "engine-unanswered-question-counts-as-success", file: "src/engine.ts", edits: [['const unanswered = spec.cls !== "read" && exitOk && !saysDone && UNANSWERED_QUESTION.test(`${stdout}\\n${stderr}`);', "const unanswered = false;"]], tests: ENGINE },
  { id: "db-delete-any-deletion-counts-as-done", file: "src/catalog/tools/databases.ts", edits: [["doneLine: `The database ${a.databaseName} has been deleted`,", "doneLine: `has been deleted`,"]], tests: ENGINE },
  { id: "engine-question-fails-a-read", file: "src/engine.ts", edits: [['const unanswered = spec.cls !== "read" && exitOk', "const unanswered = exitOk"]], tests: ENGINE },
  { id: "engine-error-line-read-from-scrubbed-output", file: "src/engine.ts", edits: [["extractServerMessage([result.stdout, result.stderr], (text) => redactor.scrub(text))", "extractServerMessage([redactor.scrub(result.stdout), redactor.scrub(result.stderr)], (text) => redactor.scrub(text))"]], tests: ENGINE },
  { id: "engine-table-cells-not-scrubbed", file: "src/engine.ts", edits: [["? parseTable(result.stdout, (cell) => redactor.scrub(cell))", "? parseTable(result.stdout)"]], tests: ENGINE },
  { id: "engine-token-not-used-with-the-answer", file: "src/engine.ts", edits: [["return { decision: answer, tokenProblem: useToken() };", "return { decision: answer, tokenProblem: null };"]], tests: ENGINE },
  { id: "engine-token-never-used-up", file: "src/engine.ts", edits: [['return this.d.tokens.consume(again.nonce) ? null : "the planToken was already used: run a dry run again";', "return null;"]], tests: ENGINE },
  { id: "engine-decision-unrecorded-when-token-lapsed", file: "src/engine.ts", edits: [["      const verdict = evaluateDecision(request, asked.decision);", "      if (asked.tokenProblem !== null) return this.refuse(spec.name, cls, profile, asked.tokenProblem);\n      const verdict = evaluateDecision(request, asked.decision);"]], tests: ENGINE },
  { id: "engine-reads-without-clpctl-not-recorded", file: "src/engine.ts", edits: [['if (!outcome.isError) this.record({ event: "end", tool: spec.name, profile: profile.name, class: spec.cls, ok: true });', ""]], tests: ENGINE },
  { id: "audit-held-back-count-waits-for-its-own-kind", file: "src/audit.ts", edits: [["    this.flush(false, minute);\n", ""]], tests: ["test/secrets.test.ts"] },
  { id: "audit-held-back-count-dated-wrong", file: "src/audit.ts", edits: [["new Date(window.minute * 60_000)", "new Date((minute - 1) * 60_000)"]], tests: ["test/secrets.test.ts"] },
  { id: "audit-flush-leaves-the-running-minute", file: "src/audit.ts", edits: [["flush(all: boolean = true,", "flush(all: boolean = false,"]], tests: ["test/secrets.test.ts"] },
  { id: "output-message-cut-before-scrub", file: "src/exec/output.ts", edits: [["sanitize(scrub(sanitize(message))).trim().slice(0, 400)", "scrub(sanitize(message).trim().slice(0, 400))"]], tests: ["test/output.test.ts"] },
  { id: "output-log-line-behind-escape-missed", file: "src/exec/output.ts", edits: [['for (const line of sanitize(text).split("\\n")) {', 'for (const line of text.split("\\n")) {']], tests: ["test/output.test.ts"] },
  { id: "output-cell-cut-before-clean", file: "src/exec/output.ts", edits: [["clean(text).slice(0, MAX_CELL)", "clean(text.slice(0, MAX_CELL))"]], tests: ["test/output.test.ts"] },
  { id: "redact-table-separator-taken-as-value", file: "src/secrets/redact.ts", edits: [['    if (!equals && text[p] === "|" && (p + 1 >= text.length || isSpace(text[p + 1] as string))) continue;\n', ""]], tests: ["test/secrets.test.ts"] },
  { id: "redact-placeholder-scrubbed-again", file: "src/secrets/redact.ts", edits: [["      if (after >= text.length || isSpace(text[after] as string) || closesAround(text, after)) continue;", ""]], tests: ["test/secrets.test.ts", "test/hardening.test.ts"] },
  { id: "redact-placeholder-prefix-trusted", file: "src/secrets/redact.ts", edits: [["      if (after >= text.length || isSpace(text[after] as string) || closesAround(text, after)) continue;", "      continue;"]], tests: ["test/secrets.test.ts"] },
  { id: "hygiene-name-beside-noreply-unchecked", file: "scripts/check-hygiene.mjs", edits: [["return name.toLowerCase() === own ? [] : [name];", "return [];"]], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-github-address-enough", file: "scripts/check-hygiene.mjs", edits: [['const byGitHub = cn === "GitHub" && ce ===', "const byGitHub = ce ==="]], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-github-as-author", file: "scripts/check-hygiene.mjs", edits: [["if (!placeholder(ae) || !(placeholder(ce) || byGitHub))", "if (!(placeholder(ae) || ae === ce) || !(placeholder(ce) || byGitHub))"]], tests: ["test/hygiene.test.ts"] },
  { id: "approval-typed-name-any-string", file: "src/policy/approval.ts", edits: [['typeof content["typed"] === "string" && content["typed"] === request.target', 'typeof content["typed"] === "string"']], tests: UNIT },
  { id: "approval-box-any-value", file: "src/policy/approval.ts", edits: [['content["approve"] === true', 'content["approve"] !== undefined']], tests: UNIT },
  { id: "approval-any-action-accepted", file: "src/policy/approval.ts", edits: [['if (decision.action !== "accept") {', "if (false) {"]], tests: UNIT },
  { id: "approval-destructive-gets-a-box", file: "src/policy/approval.ts", edits: [['const needsTyping = input.cls !== "write";', "const needsTyping = false;"]], tests: UNIT },
  { id: "approval-url-only-counts-as-form", file: "src/policy/approval.ts", edits: [["return cap.url === undefined; // `{}`: form mode only", "return true;"]], tests: UNIT },
  { id: "tokens-no-expiry", file: "src/policy/tokens.ts", edits: [["if (Number(expiry) < this.now()) {", "if (false) {"]], tests: UNIT },
  { id: "tokens-mac-not-checked", file: "src/policy/tokens.ts", edits: [["if (given.length !== expected.length || !timingSafeEqual(given, expected)) {", "if (false) {"]], tests: UNIT },
  { id: "tokens-replay-allowed", file: "src/policy/tokens.ts", edits: [["if (this.consumed.has(nonce)) {\n      return { ok: false, reason: \"the planToken was already used", "if (false) {\n      return { ok: false, reason: \"the planToken was already used"]], tests: UNIT },
  { id: "tokens-binding-ignored", file: "src/policy/tokens.ts", edits: [["\\n${binding}`)", "`)"]], tests: UNIT },
  { id: "rate-limit-never-blocks", file: "src/policy/rate.ts", edits: [["if (recent.length >= limit.max) {", "if (false) {"]], tests: UNIT },
  { id: "rate-window-never-slides", file: "src/policy/rate.ts", edits: [[".filter((t) => now - t < windowMs)", ".filter(() => true)"]], tests: UNIT },
  { id: "protect-names-case-sensitive", file: "src/policy/protect.ts", edits: [["return list.some((entry) => entry.toLowerCase() === v);", "return list.includes(value);"]], tests: UNIT },
  { id: "protect-www-stripped-once", file: "src/policy/protect.ts", edits: [['while (d.startsWith("www.")) d = d.slice(4);', 'if (d.startsWith("www.")) d = d.slice(4);']], tests: UNIT },
  { id: "protect-www-not-normalised", file: "src/policy/protect.ts", edits: [['while (d.startsWith("www.")) d = d.slice(4);', ""]], tests: UNIT },
  { id: "protect-wildcard-matches-lookalikes", file: "src/policy/protect.ts", edits: [["return d === suffix || d.endsWith(`.${suffix}`);", "return d === suffix || d.endsWith(suffix);"]], tests: UNIT },
  { id: "protect-wildcard-skips-apex", file: "src/policy/protect.ts", edits: [["return d === suffix || d.endsWith(`.${suffix}`);", "return d.endsWith(`.${suffix}`);"]], tests: UNIT },

  // ------------------------------------------------------------------ validators
  { id: "pattern-domain-unanchored", file: "src/validate/patterns.ts", edits: [["[a-z0-9]$`,\n  siteUser", "[a-z0-9]`,\n  siteUser"]], tests: UNIT },
  { id: "pattern-dbname-allows-underscore", file: "src/validate/patterns.ts", edits: [['dbName: "^[A-Za-z0-9][A-Za-z0-9-]{0,63}$"', 'dbName: "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"']], tests: UNIT },
  { id: "pattern-sitename-allows-dot", file: "src/validate/patterns.ts", edits: [['siteUser: "^[a-z][a-z0-9_-]{0,31}$"', 'siteUser: "^[a-z][a-z0-9_.-]{0,31}$"']], tests: UNIT },
  { id: "pattern-template-allows-quote", file: "src/validate/patterns.ts", edits: [['templateName: "^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-])?$"', 'templateName: "^[A-Za-z0-9]([A-Za-z0-9 ._\'-]{0,62}[A-Za-z0-9._-])?$"']], tests: UNIT },
  { id: "pattern-template-starts-with-dot", file: "src/validate/patterns.ts", edits: [['templateName: "^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,62}', 'templateName: "^[A-Za-z0-9._]([A-Za-z0-9 ._-]{0,62}']], tests: UNIT },
  { id: "pattern-filemode-setuid", file: "src/validate/patterns.ts", edits: [['fileMode: "^0?[0-7][0-7][0145]$"', 'fileMode: "^[0-7]{3,4}$"']], tests: UNIT },
  { id: "pattern-filemode-world-write", file: "src/validate/patterns.ts", edits: [['fileMode: "^0?[0-7][0-7][0145]$"', 'fileMode: "^0?[0-7][0-7][0-7]$"']], tests: UNIT },
  { id: "reserved-panel-database", file: "src/validate/patterns.ts", edits: [['"performance_schema", "clp", "cloudpanel",', '"performance_schema",']], tests: UNIT },
  { id: "port-profile-ranges-ignored", file: "src/validate/patterns.ts", edits: [["ranges.some((range) => value >= range.from && value <= range.to)", "true"]], tests: UNIT },
  { id: "port-range-upper-bound", file: "src/validate/patterns.ts", edits: [["value >= range.from && value <= range.to", "value >= range.from"]], tests: UNIT },
  { id: "file-kind-extension-ignored", file: "src/validate/patterns.ts", edits: [["return isCleanPath(value) && FILE_EXT[kind].test(value) && isUnderDirs(value, kindDirs(kind, fileDirs));", "return isCleanPath(value) && isUnderDirs(value, kindDirs(kind, fileDirs));"]], tests: UNIT },
  { id: "file-kind-subdirectory-ignored", file: "src/validate/patterns.ts", edits: [["return isCleanPath(value) && FILE_EXT[kind].test(value) && isUnderDirs(value, kindDirs(kind, fileDirs));", "return isCleanPath(value) && FILE_EXT[kind].test(value) && isUnderDirs(value, fileDirs);"]], tests: UNIT },
  { id: "file-kind-problem-extension", file: "src/validate/patterns.ts", edits: [["if (!FILE_EXT[kind].test(value)) return `must end with ${FILE_EXT_TEXT[kind]}`;", ""]], tests: UNIT },
  { id: "proxy-url-host-not-checked", file: "src/validate/patterns.ts", edits: [["if (!allowedHosts.includes(parsed.host)) return", "if (false) return"]], tests: UNIT },
  { id: "pattern-password-any-length", file: "src/validate/patterns.ts", edits: [['generatedPassword: "^[A-Za-z0-9]{32}$"', 'generatedPassword: "^[A-Za-z0-9]{1,64}$"']], tests: UNIT },
  { id: "pattern-relative-path-allows-dotdot", file: "src/validate/patterns.ts", edits: [['"^(\\\\.|[A-Za-z0-9_][A-Za-z0-9._-]{0,63}', '"^(\\\\.|[A-Za-z0-9_.][A-Za-z0-9._-]{0,63}']], tests: UNIT },
  { id: "port-denied-list-ignored", file: "src/validate/patterns.ts", edits: [["    !DENIED_APP_PORTS.includes(value)", "    true"]], tests: UNIT },
  { id: "port-privileged-allowed", file: "src/validate/patterns.ts", edits: [["value >= 1024 &&", "value >= 1 &&"]], tests: UNIT },
  { id: "path-prefix-boundary", file: "src/validate/patterns.ts", edits: [["value.startsWith(`${dir}/`)", "value.startsWith(dir)"]], tests: UNIT },
  { id: "path-dotdot-allowed", file: "src/validate/patterns.ts", edits: [['if (value.includes("..") || value.includes("//") || value.includes("/./"))', 'if (value.includes("//") || value.includes("/./"))']], tests: UNIT },
  { id: "proxy-url-path-traversal", file: "src/validate/patterns.ts", edits: [['if (path.includes("..") || path.includes("//")) return null;', ""]], tests: UNIT },
  { id: "proxy-url-port-rule", file: "src/validate/patterns.ts", edits: [["if (parsed.port !== null && parsed.port !== 80 && parsed.port !== 443 && !isAppPort(parsed.port, appPorts)) {", "if (false) {"]], tests: UNIT },
  { id: "purge-all-ambiguity", file: "src/validate/patterns.ts", edits: [['if (tags.length > 1 && tags.includes("all")) return null;', ""]], tests: UNIT },
  { id: "schema-reserved-site-users", file: "src/validate/schemas.ts", edits: [['.refine((v) => !RESERVED_SITE_USERS.includes(v), "is a reserved system name")', '.refine(() => true, "is a reserved system name")']], extraEdits: [["src/validate/option-types.ts", [["RE.siteUser.test(value) && !RESERVED_SITE_USERS.includes(value)", "RE.siteUser.test(value)"]]]], tests: UNIT },
  { id: "option-types-reserved-db-users", file: "src/validate/option-types.ts", edits: [["return RE.dbUser.test(value) && !RESERVED_DB_USERS.includes(value.toLowerCase());", "return RE.dbUser.test(value);"]], tests: UNIT },
  { id: "schema-reserved-db-users", file: "src/validate/schemas.ts", edits: [['.refine((v) => !RESERVED_DB_USERS.includes(v.toLowerCase()), "is a reserved system account")', ".refine(() => true, \"is a reserved system account\")"]], tests: UNIT },
  { id: "schema-reserved-databases", file: "src/validate/schemas.ts", edits: [["(v) => !RESERVED_DATABASES.includes(v.toLowerCase()),", "() => true,"]], extraEdits: [["src/validate/option-types.ts", [["RE.dbName.test(value) && !RESERVED_DATABASES.includes(value.toLowerCase())", "RE.dbName.test(value)"]]]], tests: UNIT },
  { id: "option-types-password-any", file: "src/validate/option-types.ts", edits: [["return RE.generatedPassword.test(value);", "return true;"]], tests: [...ENGINE, "test/catalog.test.ts", ...GATE], skip: "no drift" },
  { id: "option-types-port-leading-zero", file: "src/validate/option-types.ts", edits: [["const PORT_TEXT = /^[1-9][0-9]{0,4}$/;", "const PORT_TEXT = /^[0-9]{1,5}$/;"]], tests: [...UNIT, ...GATE], skip: "no drift" },

  // ------------------------------------------------------------------ quoting and transports
  { id: "quote-single-quote-unescaped", file: "src/exec/quote.ts", edits: [["value.replaceAll(\"'\", \"'\\\\''\")", "value"]], tests: UNIT },
  { id: "quote-control-chars-allowed", file: "src/exec/quote.ts", edits: [["if (/[\\u0000-\\u001f\\u007f]/.test(value)) {", "if (false) {"]], tests: UNIT },
  { id: "quote-any-prefix", file: "src/exec/quote.ts", edits: [["return prefix.length === 0 || (prefix.length === 2 && prefix[0] === \"sudo\" && prefix[1] === \"-n\");", "return true;"]], tests: UNIT },
  { id: "quote-any-program-path", file: "src/exec/quote.ts", edits: [["if (!PROGRAM_PATH_RE.test(parts.clpctlPath) || parts.clpctlPath.includes(\"..\")) {", "if (false) {"]], tests: UNIT },
  { id: "ssh-host-key-checking-off", file: "src/exec/transport.ts", edits: [['"StrictHostKeyChecking=yes"', '"StrictHostKeyChecking=no"']], tests: ["test/ssh.test.ts"] },
  { id: "ssh-prompts-allowed", file: "src/exec/transport.ts", edits: [['"BatchMode=yes"', '"BatchMode=no"']], tests: ["test/ssh.test.ts"] },
  { id: "ssh-forwarding-allowed", file: "src/exec/transport.ts", edits: [['"ClearAllForwardings=yes",', ""]], tests: ["test/ssh.test.ts"] },
  { id: "ssh-socket-directory-unsafe-characters", file: "src/exec/transport.ts", edits: [["|| !/^[A-Za-z0-9._/-]+$/.test(dir)", ""]], tests: ["test/ssh.test.ts"] },
  { id: "ssh-socket-shared-between-logins", file: "src/exec/transport.ts", edits: [["socketKeyOf(target, options.identityStamp)", 'socketKeyOf({ host: "x" })'], ["socketKeyOf(this.target, stamp)", 'socketKeyOf({ host: "x" })']], tests: ["test/ssh.test.ts"] },
  { id: "ssh-socket-key-ignores-the-key-file", file: "src/exec/transport.ts", edits: [["return `${stat.size}:${Math.round(stat.mtimeMs)}:${stat.ino}`;", 'return "";']], tests: ["test/ssh.test.ts"] },
  { id: "ssh-shared-connection-lingers", file: "src/exec/transport.ts", edits: [["export const CONTROL_PERSIST_SECONDS = 15;", "export const CONTROL_PERSIST_SECONDS = 600;"]], tests: ["test/ssh.test.ts"] },
  { id: "ssh-socket-key-ignores-the-identity", file: "src/exec/transport.ts", edits: [["target.identityFile ?? null, target.configFile ?? null", "null, null"]], tests: ["test/ssh.test.ts"] },
  { id: "ssh-socket-directory-not-prepared", file: "src/exec/transport.ts", edits: [["    this.prepareSocketDir(stamp); // may switch sharing off\n", ""]], tests: ["test/ssh.test.ts"] },
  { id: "site-user-login-from-the-prototype", file: "src/exec/transport.ts", edits: [["Object.hasOwn(profile.siteUserAccess, siteUser) ? profile.siteUserAccess[siteUser] : undefined", "profile.siteUserAccess[siteUser]"]], tests: ["test/ssh.test.ts"] },
  { id: "site-user-access-from-the-prototype", file: "src/catalog/tools/siteuser.ts", edits: [["!Object.hasOwn(profile.siteUserAccess, user) || ", ""]], tests: ENGINE },
  { id: "private-dir-symlink-followed", file: "src/fsutil.ts", edits: [["if (stat.isSymbolicLink() || !stat.isDirectory()) throw", "if (false) throw"]], tests: ["test/fsutil.test.ts"] },
  { id: "private-dir-foreign-owner", file: "src/fsutil.ts", edits: [["if (uid !== undefined && stat.uid !== uid) {", "if (false) {"]], tests: ["test/fsutil.test.ts"] },
  { id: "private-dir-mode-not-repaired", file: "src/fsutil.ts", edits: [["chmodSync(dir, 0o700);\n    stat = lstatSync(dir);", "stat = lstatSync(dir);"]], tests: ["test/fsutil.test.ts", "test/secrets.test.ts"] },
  { id: "ssh-host-option-injection", file: "src/exec/transport.ts", edits: [['if (target.host.startsWith("-") || /\\s/.test(target.host)) throw new Error("invalid ssh host");', ""]], tests: ["test/ssh.test.ts"] },
  { id: "process-shell-enabled", file: "src/exec/process.ts", edits: [["shell: false,", "shell: true,"]], tests: ["test/ssh.test.ts"] },

  // ------------------------------------------------------------------ configuration
  { id: "config-world-writable-file-ok", file: "src/config/load.ts", edits: [["(mode & 0o022) !== 0", "false"]], tests: ["test/config.test.ts"] },
  { id: "config-forbidden-dirs-allowed", file: "src/config/load.ts", edits: [["if (underRoot(path, FORBIDDEN_DIR_ROOTS)) {", "if (false) {"]], tests: ["test/config.test.ts"] },
  { id: "config-misspelt-env-ignored", file: "src/config/load.ts", edits: [["!ENV_NAMES.has(name.slice(\"CLOUDPANEL_MCP_\".length))", "false"]], tests: ["test/config.test.ts"] },
  { id: "config-approval-defaults-to-client", file: "src/config/load.ts", edits: [['approvalWrite: raw.approval?.write ?? "ask",', 'approvalWrite: raw.approval?.write ?? "client",']], tests: ["test/config.test.ts"] },
  { id: "config-unknown-keys-allowed", file: "src/config/load.ts", edits: [["const profileSchema = z.strictObject({", "const profileSchema = z.object({"]], tests: ["test/config.test.ts"] },
  { id: "config-shared-file-directories-allowed", file: "src/config/load.ts", edits: [["if (!allowShared && underRoot(path, SHARED_DIR_ROOTS)) {", "if (false) {"]], tests: ["test/config.test.ts"] },
  { id: "config-untrusted-flag-lifts-system-directories", file: "src/config/load.ts", edits: [["if (underRoot(path, FORBIDDEN_DIR_ROOTS)) {", "if (!allowShared && underRoot(path, FORBIDDEN_DIR_ROOTS)) {"]], tests: ["test/config.test.ts"] },
  { id: "config-site-user-login-is-not-that-user", file: "src/config/load.ts", edits: [["if (parsed.data.user !== undefined && parsed.data.user !== siteUser) {", "if (false) {"]], tests: ["test/config.test.ts"] },
  { id: "directory-roots-incomplete", file: "src/validate/patterns.ts", edits: [['"/var/spool", "/var/lock", "/var/crash", "/var/lib/php", ', ""]], tests: ["test/config.test.ts", "test/gate.test.ts"], skip: "no drift" },
  { id: "denied-ports-forget-the-admin-apis", file: "src/validate/patterns.ts", edits: [["4369, 4505, 4506, 4646, // Erlang port mapper, Salt, Nomad", "4369, 4505, 4506, // Erlang port mapper, Salt"], ["8001, 8086, 8200, 8443, 8500, // kubectl proxy, InfluxDB, Vault, the panel, Consul", "8443, // the panel"]], tests: UNIT },
  { id: "warning-untrusted-file-directories", file: "src/policy/warnings.ts", edits: [["if (p.allowUntrustedFileDirs) {", "if (false) {"]], tests: ["test/cli.test.ts"] },
  { id: "config-app-port-denied-single", file: "src/config/load.ts", edits: [["if (m[2] === undefined && !isPortAllowedAtAll(from)) {", "if (false) {"]], tests: ["test/config.test.ts"] },
  { id: "config-app-port-range-direction", file: "src/config/load.ts", edits: [["if (!(from >= 1024 && to <= 65535 && from <= to))", "if (false)"]], tests: ["test/config.test.ts"] },
  { id: "config-json-error-echoes-input", file: "src/config/load.ts", edits: [["is not valid JSON${at === undefined ? \"\" : ` (near character ${at})`}`", "is not valid JSON (${error instanceof Error ? error.message : \"\"})`"]], tests: ["test/config.test.ts"] },
  { id: "config-writes-allowed-by-default", file: "src/config/load.ts", edits: [["const allow = new Set<ChangingClass>();", 'const allow = new Set<ChangingClass>(["write"]);']], tests: ["test/config.test.ts"] },

  // ------------------------------------------------------------------ secrets, redaction, audit, output
  { id: "secrets-file-world-readable", file: "src/secrets/store.ts", edits: [['{ flag: "wx", mode: 0o600 });\n    } catch (error) {\n      throw new SecretsError(`cannot write the secrets file (${(error as NodeJS.ErrnoException).code ?? "error"})`);\n    }\n    try {\n      chmodSync(path, 0o600);', '{ flag: "wx", mode: 0o644 });\n    } catch (error) {\n      throw new SecretsError(`cannot write the secrets file (${(error as NodeJS.ErrnoException).code ?? "error"})`);\n    }\n    try {\n      chmodSync(path, 0o644);']], tests: ["test/secrets.test.ts", "test/engine.test.ts"] },
  { id: "secrets-file-overwritten", file: "src/secrets/store.ts", edits: [['writeFileSync(path, `${JSON.stringify(body, null, 2)}\\n`, { flag: "wx", mode: 0o600 });\n    } catch (error) {\n      throw new SecretsError(`cannot write the secrets file (${(error as NodeJS.ErrnoException).code ?? "error"})`);\n    }\n    try {\n      chmodSync(path, 0o600);\n    } catch {\n      // Windows\n    }\n    let current', 'writeFileSync(path, `${JSON.stringify(body, null, 2)}\\n`, { flag: "w", mode: 0o600 });\n    } catch (error) {\n      throw new SecretsError(`cannot write the secrets file (${(error as NodeJS.ErrnoException).code ?? "error"})`);\n    }\n    try {\n      chmodSync(path, 0o600);\n    } catch {\n      // Windows\n    }\n    let current']], tests: ["test/secrets.test.ts"] },
  { id: "secrets-unsafe-file-names", file: "src/secrets/store.ts", edits: [["if (!SAFE_NAME.test(request.kind) || !SAFE_NAME.test(request.target) || !SAFE_NAME.test(this.profile)) {\n      throw new SecretsError(\"the secret's target is not usable as a file name, so nothing is run\");", "if (false) {\n      throw new SecretsError(\"the secret's target is not usable as a file name, so nothing is run\");"]], tests: ["test/secrets.test.ts"] },
  { id: "secrets-biased-password", file: "src/secrets/store.ts", edits: [["if (byte >= 248) continue;", ""]], tests: ["test/secrets.test.ts"] },
  { id: "redact-short-secrets", file: "src/secrets/redact.ts", edits: [["if (secret.length >= 8) this.secrets.add(secret);", "this.secrets.add(secret);"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-password-options", file: "src/secrets/redact.ts", edits: [["return scrubPasswordOptions(out);", "return out;"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-sanitize-after-not-before", file: "src/secrets/redact.ts", edits: [["    let out = sanitize(text);", "    let out = text;"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-index-shifts-with-lower-case", file: "src/secrets/redact.ts", edits: [["const at = indexOfPassword(text, from);", "const at = text.toLowerCase().indexOf(WORD, from);"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-quoted-value-with-spaces", file: "src/secrets/redact.ts", edits: [["      if (close >= valueStart) {", "      if (false) {"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-escaped-quotes", file: "src/secrets/redact.ts", edits: [['if (quote === "\\\\" && (text[valueStart + 1] === \'"\' || text[valueStart + 1] === "\'")) {', "if (false) {"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-value-stops-at-a-quote", file: "src/secrets/redact.ts", edits: [["      while (valueEnd < text.length && !isSpace(text[valueEnd] as string)) valueEnd += 1;\n    }\n    if (valueEnd === valueStart) continue;", "      while (valueEnd < text.length && !isSpace(text[valueEnd] as string) && text[valueEnd] !== \"'\" && text[valueEnd] !== '\"') valueEnd += 1;\n    }\n    if (valueEnd === valueStart) continue;"]], tests: ["test/secrets.test.ts"] },
  { id: "redact-value-after-spaced-equals", file: "src/secrets/redact.ts", edits: [['    if (equals) {\n      p += 1;\n      while (isBlank(text[p])) p += 1;', '    if (equals) {\n      p += 1;']], tests: ["test/secrets.test.ts"] },
  { id: "redact-name-scan-unbounded", file: "src/secrets/redact.ts", edits: [["while (start > 0 && isNameChar(text[start - 1]) && steps < MAX_OPTION_NAME) {", "while (start > 0 && isNameChar(text[start - 1])) {"]], tests: ["test/secrets.test.ts"] },
  { id: "audit-not-redacted", file: "src/audit.ts", edits: [["this.redactor.scrub(value).slice(0, MAX_FIELD)", "value.slice(0, MAX_FIELD)"]], tests: ["test/secrets.test.ts"] },
  { id: "audit-file-world-readable", file: "src/audit.ts", edits: [['{ flag: "a", mode: 0o600 }', '{ flag: "a", mode: 0o644 }']], extraEdits: [["src/audit.ts", [["if ((statSync(this.path).mode & 0o777) !== 0o600) chmodSync(this.path, 0o600);", ""]]]], tests: ["test/secrets.test.ts"] },
  { id: "sanitize-keeps-escapes", file: "src/exec/output.ts", edits: [['.replace(/\\u001b\\[[0-9;?]*[ -/]*[@-~]/g, "")', ""]], tests: ["test/output.test.ts", "test/engine.test.ts"] },
  { id: "sanitize-keeps-bidi", file: "src/exec/output.ts", edits: [['.replace(INVISIBLE, "")', ""]], tests: ["test/output.test.ts"] },
  { id: "sanitize-keeps-format-characters", file: "src/exec/output.ts", edits: [["[\\p{Cc}\\p{Cf}\\p{Co}", "[\\p{Cc}\\p{Co}"]], tests: ["test/output.test.ts"] },
  { id: "sanitize-keeps-default-ignorables", file: "src/exec/output.ts", edits: [["\\p{Variation_Selector}\\p{Default_Ignorable_Code_Point}]", "\\p{Variation_Selector}]"]], tests: ["test/output.test.ts"] },
  { id: "sanitize-keeps-private-use", file: "src/exec/output.ts", edits: [["\\p{Cf}\\p{Co}\\p{Cn}", "\\p{Cf}\\p{Cn}"]], tests: ["test/output.test.ts"] },
  { id: "table-rows-unbounded", file: "src/exec/output.ts", edits: [["dataLines.slice(1, MAX_ROWS + 1)", "dataLines.slice(1)"]], tests: ["test/output.test.ts"] },
  { id: "table-cells-unbounded", file: "src/exec/output.ts", edits: [["clean(text).slice(0, MAX_CELL)", "clean(text)"]], tests: ["test/output.test.ts", "test/hardening.test.ts"] },
  { id: "truncate-unbounded", file: "src/exec/output.ts", edits: [["if (text.length <= limit) return text;", "return text;"]], tests: ["test/output.test.ts", "test/engine.test.ts"] },
  { id: "server-error-severity", file: "src/exec/output.ts", edits: [["const severe = typeof level === \"string\" && SEVERE_LEVELS.includes(level.toUpperCase());", "const severe = false;"]], tests: ["test/output.test.ts", "test/engine.test.ts"] },

  // ------------------------------------------------------------------ catalogue
  { id: "catalog-destructive-without-interaction-flag", file: "src/catalog/define.ts", edits: [['requiresUserInteraction: def.cls === "destructive" || def.cls === "admin",', "requiresUserInteraction: false,"]], tests: ["test/catalog.test.ts"] },
  { id: "catalog-site-delete-forced-flag", file: "src/catalog/tools/sites.ts", edits: [['    flags: ["--force"],\n    protectOptions', '    flags: [],\n    protectOptions']], tests: ["test/catalog.test.ts", "test/engine.test.ts"] },
  { id: "catalog-site-delete-not-destructive", file: "src/catalog/tools/sites.ts", edits: [['cls: "destructive",\n    title: "Delete a site",', 'cls: "write",\n    title: "Delete a site",']], tests: ["test/catalog.test.ts", "test/engine.test.ts"] },

  // ------------------------------------------------------------------ the hardened-mode gate (template)
  { id: "gate-line-length", file: "hardening/gate.template.sh", edits: [["(( ${#cmd} <= 4096 )) || refuse 'command too long'", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-character-set", file: "hardening/gate.template.sh", edits: [["[[ $cmd =~ $RE_CHARS ]] || refuse 'the command contains a character that is never allowed'", ""]], tests: GATE, skip: "no drift", equivalent: "defence in depth: every character outside the set is also refused by the option grammar and the value patterns, so no input is decided by this line alone" },
  { id: "gate-scope", file: "hardening/gate.template.sh", edits: [['[[ $CMD_SCOPE == "$SCOPE" ]] || refuse "the command $sub is not allowed for this key"', ""]], tests: GATE, skip: "no drift" },
  { id: "gate-destructive-ceiling", file: "hardening/gate.template.sh", edits: [['destructive) [[ $ALLOW_WRITE == 1 && $ALLOW_DESTRUCTIVE == 1 ]] ||', "destructive) true ||"]], tests: GATE, skip: "no drift" },
  { id: "gate-admin-ceiling", file: "hardening/gate.template.sh", edits: [['admin) [[ $ALLOW_WRITE == 1 && $ALLOW_ADMIN == 1 ]] ||', "admin) true ||"]], tests: GATE, skip: "no drift" },
  { id: "gate-duplicate-option", file: "hardening/gate.template.sh", edits: [['[[ $seen != *" $name "* ]] || refuse "the option --$name is given twice"', ""]], tests: GATE, skip: "no drift" },
  { id: "gate-required-options", file: "hardening/gate.template.sh", edits: [['[[ $seen == *" ${pair%%:*} "* ]] || refuse "the required option --${pair%%:*} is missing"', ""]], tests: GATE, skip: "no drift" },
  { id: "gate-value-validation", file: "hardening/gate.template.sh", edits: [['valid_value "$type" "$value" || refuse "the value of --$name is not valid"', ""]], tests: GATE, skip: "no drift" },
  { id: "gate-protected-targets", file: "hardening/gate.template.sh", edits: [['if protected "$kind" "$part"; then', "if false; then"]], tests: GATE, skip: "no drift" },
  { id: "gate-protected-list-entries", file: "hardening/gate.template.sh", edits: [["part=${rest%%,*}\n      rest=${rest#*,}", "part=${rest%,}\n      rest="]], tests: GATE, skip: "no drift" },
  { id: "gate-www-stripped-once", file: "hardening/gate.template.sh", edits: [["  while [[ $d == www.* ]]; do\n    d=${d#www.}\n  done", "  if [[ $d == www.* ]]; then\n    d=${d#www.}\n  fi"]], tests: GATE, skip: "no drift" },
  { id: "gate-settings-domain-unchecked", file: "hardening/gate.template.sh", edits: [["valid_domain \"$entry\" || refuse 'a PROTECT_DOMAINS setting of the gate is malformed (a lowercase domain name, or *.domain)'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-settings-site-user-unchecked", file: "hardening/gate.template.sh", edits: [["[[ $(lower \"$entry\") =~ $RE_siteUser ]] || refuse 'a PROTECT_SITE_USERS setting of the gate is malformed'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-settings-database-unchecked", file: "hardening/gate.template.sh", edits: [["[[ $entry =~ $RE_dbName ]] || refuse 'a PROTECT_DATABASES setting of the gate is malformed'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-settings-panel-user-unchecked", file: "hardening/gate.template.sh", edits: [["[[ $entry =~ $RE_panelUser ]] || refuse 'a PROTECT_PANEL_USERS setting of the gate is malformed'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-file-dir-settings-unchecked", file: "hardening/gate.template.sh", edits: [["valid_file_dir \"$entry\" || refuse 'an ALLOWED_FILE_DIRS setting of the gate is not a usable directory (a clean path two levels deep, in no system place and no place other accounts write; make it root-owned)'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-file-dir-system-places", file: "hardening/gate.template.sh", edits: [['under_root "$dir" "${FORBIDDEN_DIR_ROOTS[@]}" && return 1', "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-file-dir-shared-places", file: "hardening/gate.template.sh", edits: [['under_root "$dir" "${SHARED_DIR_ROOTS[@]}" && return 1', "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-file-dir-depth", file: "hardening/gate.template.sh", edits: [["[[ $dir =~ ^/[^/]+/[^/]+ ]] || return 1", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-proxy-host-settings-unchecked", file: "hardening/gate.template.sh", edits: [["[[ $entry =~ $RE_PROXY_HOST || $entry =~ $RE_PROXY_HOST6 ]] || refuse 'a PROXY_HOSTS setting of the gate is malformed (a lowercase host name or an IPv6 address)'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-app-port-settings-unchecked", file: "hardening/gate.template.sh", edits: [["valid_port_entry \"$entry\" || refuse 'an APP_PORTS setting of the gate is malformed (a port or low-high from 1024 to 65535, never a port the server refuses)'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-app-port-setting-names-a-denied-port", file: "hardening/gate.template.sh", edits: [["      (( 10#$low == denied )) && return 1\n", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-site-user-gate-as-root", file: "hardening/gate.template.sh", edits: [["[[ $(id -u 2>/dev/null) != 0 ]] || refuse 'a site-user gate does not run as root'", "true"]], tests: GATE, skip: "no drift" },
  { id: "gate-site-user-gate-as-system-account", file: "hardening/gate.template.sh", edits: [['if in_list "$me" "${RESERVED_SITE_USERS[@]}"; then', "if false; then"]], tests: GATE, skip: "no drift" },
  { id: "gate-site-user-scope-unprotected", file: "hardening/gate.template.sh", edits: [['if protected siteUser "$me"; then', "if false; then"]], tests: GATE, skip: "no drift" },
  { id: "gate-reserved-db-users", file: "hardening/gate.template.sh", edits: [['dbUser) [[ $value =~ $RE_dbUser ]] && ! in_list "$(lower "$value")" "${RESERVED_DB_USERS[@]}" ;;', "dbUser) [[ $value =~ $RE_dbUser ]] ;;"]], tests: GATE, skip: "no drift" },
  { id: "gate-protected-names-case-sensitive", file: "hardening/gate.template.sh", edits: [['database) in_list_ci "$2"', 'database) in_list "$2"']], tests: GATE, skip: "no drift" },
  { id: "gate-protected-site-users", file: "hardening/gate.template.sh", edits: [['siteUser) in_list_ci "$2" ${PROTECT_SITE_USERS[@]+"${PROTECT_SITE_USERS[@]}"} ;;', "siteUser) return 1 ;;"]], tests: GATE, skip: "no drift" },
  { id: "gate-protected-domains-case-sensitive", file: "hardening/gate.template.sh", edits: [["    entry=$(lower \"$entry\")\n", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-settings-not-checked", file: "hardening/gate.template.sh", edits: [["  check_settings\n  local cmd", "  local cmd"]], tests: GATE, skip: "no drift" },
  { id: "gate-path-from-the-caller", file: "hardening/gate.template.sh", edits: [["PATH=/usr/bin:/bin\nexport PATH\n", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-file-subdirectory", file: "hardening/gate.template.sh", edits: [['[[ $value == "$dir/$sub/"* ]]', '[[ $value == "$dir"/* ]]']], tests: GATE, skip: "no drift" },
  { id: "gate-file-extension", file: "hardening/gate.template.sh", edits: [["(( ok == 0 )) || return 1\n  [[ $value =~ $ext ]]", "(( ok == 0 )) || return 1\n  return 0"]], tests: GATE, skip: "no drift" },
  { id: "gate-app-port-list", file: "hardening/gate.template.sh", edits: [["(( 10#$value >= 10#$low && 10#$value <= 10#$high )) && return 0", "return 0"]], tests: GATE, skip: "no drift" },
  { id: "gate-app-port-upper-bound", file: "hardening/gate.template.sh", edits: [["(( 10#$value >= 10#$low && 10#$value <= 10#$high )) && return 0", "(( 10#$value >= 10#$low )) && return 0"]], tests: GATE, skip: "no drift" },
  { id: "gate-newline-in-lists", file: "hardening/gate.template.sh", edits: [["&& $value != *$'\\n'* ]] || return 1\n  IFS=, read -r -a parts <<<\"$value\"\n  (( ${#parts[@]} >= 1 && ${#parts[@]} <= 20 )) || return 1\n  for part in \"${parts[@]}\"; do\n    valid_domain", "]] || return 1\n  IFS=, read -r -a parts <<<\"$value\"\n  (( ${#parts[@]} >= 1 && ${#parts[@]} <= 20 )) || return 1\n  for part in \"${parts[@]}\"; do\n    valid_domain"]], tests: GATE, skip: "no drift" },
  { id: "gate-sites-only-for-users", file: "hardening/gate.template.sh", edits: [["if [[ $sub == user:add && $seen == *' sites '* && ${ARG_role-} != user ]]; then", "if false; then"]], tests: GATE, skip: "no drift" },
  { id: "gate-sudo-for-site-users", file: "hardening/gate.template.sh", edits: [["[[ $SCOPE == root ]] || refuse 'sudo is not allowed for this key'", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-inventory-not-enabled", file: "hardening/gate.template.sh", edits: [["[[ $SCOPE == root && $ALLOW_INVENTORY == 1 ]] || refuse 'the inventory script is not enabled in this gate'", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-port-denied-list", file: "hardening/gate.template.sh", edits: [["(( value == denied )) && return 1", ""]], tests: GATE, skip: "no drift" },
  { id: "gate-reserved-site-users", file: "hardening/gate.template.sh", edits: [['siteUser) [[ $value =~ $RE_siteUser ]] && ! in_list "$value" "${RESERVED_SITE_USERS[@]}" ;;', "siteUser) [[ $value =~ $RE_siteUser ]] ;;"]], tests: GATE, skip: "no drift" },

  // ------------------------------------------------------------------ the catalogue's protect rule
  { id: "catalog-lets-encrypt-names-unprotected", file: "src/catalog/tools/certs.ts", edits: [['protect: [a.domainName, ...(extra ?? [])].map((value) => ({ kind: "domain" as const, value })),', "protect: [],"]], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-install-certificate-unprotected", file: "src/catalog/tools/certs.ts", edits: [['undo: "install the previous certificate again",\n      protect: [{ kind: "domain", value: a.domainName }],', 'undo: "install the previous certificate again",\n      protect: [],']], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-db-add-unprotected", file: "src/catalog/tools/databases.ts", edits: [['protect: [\n        { kind: "domain", value: a.domainName },\n        { kind: "database", value: a.databaseName },\n      ],', "protect: [],"]], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-db-export-unprotected", file: "src/catalog/tools/databases.ts", edits: [['undo: `delete the file ${a.file} on the server`,\n      protect: [{ kind: "database", value: a.databaseName }],', "undo: `delete the file ${a.file} on the server`,\n      protect: [],"]], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-new-site-user-unprotected", file: "src/catalog/tools/sites.ts", edits: [['  { kind: "siteUser", value: user },\n];', "];"]], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-new-site-domain-unprotected", file: "src/catalog/tools/sites.ts", edits: [['const protectNew = (domain: string, user: string): ProtectCheck[] => [\n  { kind: "domain", value: domain },', "const protectNew = (domain: string, user: string): ProtectCheck[] => ["]], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-user-add-sites-unprotected", file: "src/catalog/tools/users.ts", edits: [['...(a.sites ?? []).map((value) => ({ kind: "domain" as const, value })),', ""]], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-varnish-purge-unprotected", file: "src/catalog/tools/siteuser.ts", edits: [['siteUser: a.siteUser,\n      protect: [{ kind: "siteUser", value: a.siteUser }],\n    }),\n  }),\n];', 'siteUser: a.siteUser,\n      protect: [],\n    }),\n  }),\n];']], tests: [...HARDENING, "test/catalog.test.ts"] },
  { id: "catalog-app-port-allowlist-skipped", file: "src/catalog/tools/sites.ts", edits: [['check: (a, p) => portProblem("appPort", Number(a["appPort"]), p),', ""]], tests: HARDENING },

  // ------------------------------------------------------------------ the inventory script
  { id: "hygiene-default-ignorables-allowed", file: "scripts/check-hygiene.mjs", edits: [["\\p{Variation_Selector}\\p{Default_Ignorable_Code_Point}]", "\\p{Variation_Selector}]"]], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-format-characters-allowed", file: "scripts/check-hygiene.mjs", edits: [["[\\p{Cc}\\p{Cf}\\p{Co}", "[\\p{Cc}\\p{Co}"]], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-private-patterns-on-noreply-identity-skipped", file: "scripts/check-hygiene.mjs", edits: [["re.test(body)) add(at", "false) add(at"]], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-history-contents-unread", file: "scripts/check-hygiene.mjs", edits: [["if (historyContent) {", "if (false) {"]], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-prepack-allowed", file: "scripts/check-hygiene.mjs", edits: [['"prepublish", "prepack"]', '"prepublish"]']], tests: ["test/hygiene.test.ts"] },
  { id: "hygiene-binary-files-skipped-silently", file: "scripts/check-hygiene.mjs", edits: [['add(file, "is a binary file and is not scanned: keep binary files out of the repository");', ""]], tests: ["test/hygiene.test.ts"] },
  { id: "inventory-accepts-arguments", file: "inventory/cloudpanel-mcp-inventory", edits: [['if [ "$#" -ne 0 ]; then', "if false; then"]], tests: INVENTORY },
  { id: "inventory-certificate-outside-dir", file: "inventory/cloudpanel-mcp-inventory", edits: [['index(certfile, certdir "/") == 1 && ', ""]], tests: INVENTORY },
  { id: "inventory-backslash-guard", file: "inventory/cloudpanel-mcp-inventory", edits: [[' && index(root, "\\\\") == 0) {', ") {"]], tests: INVENTORY, equivalent: "only the awk of busybox reads a backslash inside [...] as part of the set; mawk, gawk and BSD awk reject it by themselves, so no test on those awks can see the guard" },
  { id: "inventory-no-file-limit", file: "inventory/cloudpanel-mcp-inventory", edits: [['[ "$count" -le "$MAX_FILES" ] || break', ""]], tests: INVENTORY },
  { id: "inventory-no-size-limit", file: "inventory/cloudpanel-mcp-inventory", edits: [['[ "$size" -le "$MAX_BYTES" ] || continue', ""]], tests: INVENTORY },
  { id: "inventory-comments-read", file: "inventory/cloudpanel-mcp-inventory", edits: [['function clean(s) { sub(/#.*/, "", s); return s }', "function clean(s) { return s }"]], tests: INVENTORY },
  { id: "inventory-root-path-unchecked", file: "inventory/cloudpanel-mcp-inventory", edits: [['root ~ /^\\/home\\/[a-z][a-z0-9_-]*\\/htdocs\\/[A-Za-z0-9._\\/-]+$/ && root !~ /\\.\\./', "1"]], tests: INVENTORY },
];

function usage() {
  process.stderr.write("usage: mutation-check.mjs [--list] [--check] [--only id,id] [--jobs N]\n");
  process.exit(2);
}

const args = process.argv.slice(2);
if (args.includes("--help")) usage();
const jobsIndex = args.indexOf("--jobs");
const jobs = jobsIndex >= 0 ? Number(args[jobsIndex + 1]) : 4;
const onlyIndex = args.indexOf("--only");
const only = onlyIndex >= 0 ? new Set((args[onlyIndex + 1] ?? "").split(",")) : null;
if (!Number.isInteger(jobs) || jobs < 1) usage();

if (args.includes("--list")) {
  for (const m of MUTANTS) process.stdout.write(`${m.id}\n`);
  process.stdout.write(`${MUTANTS.length} mutants\n`);
  process.exit(0);
}

if (args.includes("--check")) {
  // no tests: only that every text a mutant replaces still exists in the code
  let bad = 0;
  for (const m of MUTANTS) {
    for (const [file, edits] of [[m.file, m.edits], ...(m.extraEdits ?? [])]) {
      const text = readFileSync(join(ROOT, file), "utf8");
      for (const [find] of edits) {
        if (!text.includes(find)) {
          bad += 1;
          process.stdout.write(`BROKEN ${m.id}: not found in ${file}: ${JSON.stringify(find.slice(0, 80))}\n`);
        }
      }
    }
  }
  process.stdout.write(`${MUTANTS.length} mutants checked, ${bad} broken\n`);
  process.exit(bad > 0 ? 1 : 0);
}

const ids = new Set();
for (const m of MUTANTS) {
  if (ids.has(m.id)) throw new Error(`duplicate mutant id ${m.id}`);
  ids.add(m.id);
}
if (only !== null) for (const id of only) if (!ids.has(id)) throw new Error(`unknown mutant ${id}`);

function applyEdits(dir, file, edits) {
  const path = join(dir, file);
  let text = readFileSync(path, "utf8");
  for (const [find, replace] of edits) {
    const at = text.indexOf(find);
    if (at < 0) throw new Error(`the text to mutate was not found in ${file}: ${JSON.stringify(find.slice(0, 80))}`);
    text = text.slice(0, at) + replace + text.slice(at + find.length);
  }
  writeFileSync(path, text);
  return path;
}

function syntaxOk(path) {
  if (extname(path) === ".ts") {
    if (typeof stripTypeScriptTypes !== "function") return true; // older Node: the tests will notice a parse error anyway
    try {
      stripTypeScriptTypes(readFileSync(path, "utf8"));
      return true;
    } catch {
      return false;
    }
  }
  if (extname(path) === ".mjs") return spawnSync(process.execPath, ["--check", path], { encoding: "utf8" }).status === 0;
  if (path.endsWith(".template.sh")) return true; // not valid bash by itself: the generated gate is what the tests parse
  if (path.endsWith(".sh")) return spawnSync("bash", ["-n", path], { encoding: "utf8" }).status === 0;
  return spawnSync("sh", ["-n", path], { encoding: "utf8" }).status === 0;
}

function run(command, argv, cwd, timeoutMs) {
  return new Promise((resolveRun) => {
    const child = spawn(command, argv, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => { out += d; if (out.length > 200_000) out = out.slice(-100_000); });
    child.stderr.on("data", (d) => { out += d; if (out.length > 200_000) out = out.slice(-100_000); });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("close", (code, signal) => { clearTimeout(timer); resolveRun({ code, signal, out }); });
  });
}

async function runMutant(m) {
  const dir = mkdtempSync(join(tmpdir(), "clpm-"));
  try {
    for (const entry of COPY) if (existsSync(join(ROOT, entry))) cpSync(join(ROOT, entry), join(dir, entry), { recursive: true });
    symlinkSync(join(ROOT, "node_modules"), join(dir, "node_modules"));
    const touched = [applyEdits(dir, m.file, m.edits)];
    for (const [file, edits] of m.extraEdits ?? []) touched.push(applyEdits(dir, file, edits));
    for (const path of touched) if (!syntaxOk(path)) return { id: m.id, status: "broken", detail: "the mutated file does not parse" };
    const argv = ["--test", "--test-force-exit", "--test-timeout=150000", ...(m.skip ? [`--test-skip-pattern=${m.skip}`] : []), ...m.tests];
    const result = await run(process.execPath, argv, dir, 280_000);
    if (result.signal === "SIGKILL") return { id: m.id, status: "killed", detail: "timeout" };
    return result.code === 0 ? { id: m.id, status: "survived", detail: "" } : { id: m.id, status: "killed", detail: "" };
  } catch (error) {
    return { id: m.id, status: "broken", detail: error instanceof Error ? error.message : String(error) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const queue = MUTANTS.filter((m) => only === null || only.has(m.id));
const results = [];
let next = 0;
const started = Date.now();
async function worker() {
  while (next < queue.length) {
    const m = queue[next++];
    const r = await runMutant(m);
    if (r.status === "survived" && m.equivalent !== undefined) {
      r.status = "equivalent";
      r.detail = m.equivalent;
    }
    results.push(r);
    process.stdout.write(`${{ killed: "killed  ", survived: "SURVIVED", equivalent: "equivalen", broken: "BROKEN  " }[r.status]} ${r.id}${r.detail ? `  (${r.detail})` : ""}\n`);
  }
}
await Promise.all(Array.from({ length: Math.min(jobs, queue.length) }, worker));

const killed = results.filter((r) => r.status === "killed").length;
const equivalent = results.filter((r) => r.status === "equivalent").length;
const survived = results.filter((r) => r.status === "survived");
const broken = results.filter((r) => r.status === "broken");
process.stdout.write(`\n${killed} of ${results.length} mutants killed in ${Math.round((Date.now() - started) / 1000)} s; ${equivalent} documented as equivalent; ${survived.length} survived; ${broken.length} broken\n`);
if (survived.length > 0) process.stdout.write(`survivors: ${survived.map((r) => r.id).join(", ")}\n`);
if (broken.length > 0) process.stdout.write(`broken (fix the mutant): ${broken.map((r) => `${r.id}: ${r.detail}`).join("; ")}\n`);
process.exit(survived.length > 0 || broken.length > 0 ? 1 : 0);
