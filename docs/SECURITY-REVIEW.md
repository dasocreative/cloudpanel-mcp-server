# Security review

This page records how the server was reviewed before its first release, what the reviewers found, and what was done about it. It is written for people who
want to judge the design, not as a certificate: a review finds what the reviewers thought to look for.

## Method

- **Independent reviewers.** Each round used several reviewers that had no part in writing the code: read-only agents given the repository and a narrow area,
  not the author's conclusions. They were asked to try to break the guarantees in [SPEC.md](SPEC.md) (a model that cannot approve for the human, cannot reach a
  shell, cannot read a secret, cannot widen what it may touch) and to report each finding with the file, the line, a concrete exploit and a severity.
- **Four areas in round 1, three in round 2:** (1) injection, validation and quoting; (2) approval, authorisation and state (tokens, protected targets, rate limits, the audit
  log); (3) secrets, files and what the model gets to read back; (4) the hardened-mode gate, the inventory script, CI workflows and the supply chain. Round 2 used three fresh reviewers on the fixed code (injection and the gate;
  approval and state; secrets, files, output, supply chain and CI), told nothing of round 1.
- **Triage.** Every finding was classified high, medium or low/info. Every high and medium finding was fixed, with a test that fails without the fix and, where
  the fix is a guard, a mutant in [`scripts/mutation-check.mjs`](../scripts/mutation-check.mjs) that removes the guard and must be noticed by a test.
  Low and informational findings were fixed where cheap and documented where not.
- **What the reviewers did not find** is as important as what they did: in no area did a reviewer find a way for the model to approve an action for the human,
  to supply or replay a plan token, to put an option or a shell word on a command line, or to obtain a generated password.

## Round 1: findings and what was done

### High

| Finding | Fix | Test |
| ------- | --- | ---- |
| **The master database credentials could be returned to the model.** If saving the output of `db:show:master-credentials` to its private file failed, the tool fell back to returning the output. | Whether output is shown is decided by the plan (`captureToFile`), never by whether saving worked: stdout, stderr and the server's message are all hidden, on success and on every failure path. | `test/hardening.test.ts` ("output that holds secrets"): saving fails, the command fails, success; mutants `engine-secret-output-shown*`. |
| **A protected site user or database did not protect a site from `site:delete`.** CloudPanel removes a site's user and databases together with the site, but only the domain was checked. | The rule is now stated where it matters: the approval text lists the databases and the user that go with the site; the tool description, the README, the specification, `clp_server_info` and `--check-config` say that a site must be protected by its **domain**, and warn when a profile lists protected site users or databases without the domain. | `test/cli.test.ts`, `test/protection.test.ts` ("clp_server_info"). |

### Medium

| Finding | Fix | Test |
| ------- | --- | ---- |
| **Protection was applied to some tools, not to all.** A protected domain could still receive a Let's Encrypt or custom certificate, a new database, or be named in a new site or panel user. | One uniform rule: every changing tool that takes a domain, a site user, a database or a panel user checks the matching protect list, and a test fails if a tool is added without it. The gate enforces the same lists, including each entry of a list option, without regard to case. | `test/protection.test.ts` ("the protect rule is uniform", one test per tool); gate tests; mutants `catalog-*-unprotected`, `gate-protected-*`. |
| **A database export could be turned into other files.** `db:export` wrote anywhere inside a file directory, so a dump (whose content an attacker may influence) could be installed as a vhost template (NGINX configuration) or a certificate, and the panel's own database could be exported. | Each kind of file has its own subdirectory and extensions (`dumps/`, `certs/`, `templates/`); the tools can write only into `dumps/`; the panel database (`clp`) and the system databases cannot be exported or imported into. The gate checks the same. | `test/protection.test.ts` ("files", "the chain from the review is cut"); `test/gate.test.ts`; mutants `file-kind-*`, `gate-file-*`, `reserved-panel-database`. |
| **The port denylist was not enough.** Anything not on a short list of database ports could be published through a reverse proxy or a Node.js or Python site. | A per-profile allowlist (`appPorts`, by default only the usual web-app ports) with the old denylist (extended) as a floor that no setting lifts. The gate has the same list. | `test/patterns.test.ts`, `test/protection.test.ts` ("application ports"), `test/gate.test.ts`; mutants `port-*`, `gate-app-port-*`, `config-app-port-*`. |
| **A regular expression that backtracks.** The redactor that removes `--...password...=value` from the server's text could take quadratic time on a long run of hyphens, and the text comes from the server. | A linear scan with bounded steps. | `test/secrets.test.ts` (linear time on hostile text, equivalence on the cases that matter); mutant `redact-name-scan-unbounded`. |
| **Invisible characters survived.** The cleaning of server text removed control characters and bidirectional marks but not tag characters, variation selectors, private-use and unassigned code points, which are readable by a model and invisible to a person. | Cleaning is defined by Unicode category (control, format, private-use, unassigned, surrogate, separators, variation selectors). | `test/output.test.ts`; mutants `sanitize-keeps-*`. |
| **Text from the server was outside the "untrusted" label and the size bound.** Parsed tables and the server's error message sat at the top level of the result. | Everything that comes from the server is in one object, `output`, labelled untrusted, cleaned and bounded (500 rows, 20 columns, 200 characters a cell). The engine's own `error` never carries server text. | `test/hardening.test.ts` ("where server text goes"); mutants `table-*-unbounded`. |
| **The gate's write ceiling is an unprivileged shell for a stolen key.** The holder of a key limited to write commands can create a site user with a password of their choosing. | Documented in the README ("What the gate cannot do") with the mitigations that work: a separate read-only profile and key, no SSH password logins, protected targets in the gate. This is a property of the design, not a defect that code can remove. | – |
| **The release workflow ran repository code with the right to publish.** | Two jobs: the one that builds and tests holds no secret and no id-token; the one that publishes runs no repository code and publishes the exact tarball the first job produced, after checking its name, version and visibility. Releases run only from the default branch, with no cache. | `test/workflows.test.ts`. |

### Low and informational

Fixed, each with a test unless it is a documentation change:

- The ssh connection-sharing directory is created privately before use; a state directory that is a symbolic link, belongs to someone else or is open to others
  is refused or repaired (`test/fsutil.test.ts`, `test/ssh.test.ts`); characters that ssh would expand in the socket path switch sharing off.
- Arguments are bounded before any pattern runs on them (size, depth, number of nodes), and a hostile object that throws when read is refused, not crashed on.
- Site-user logins are found by own property, so a site user called `constructor` cannot reach `Object.prototype`.
- A failing audit write for an approval refuses the command; the approval question's key belongs to its plan token; only one question per profile waits at a
  time; the number of questions per profile is limited (`rateLimits.ask`), answered or not, and counted once in the protocol era that re-runs a call.
- Names in protect lists match without regard to case; file modes cannot carry setuid, setgid, sticky or world-write bits; vhost template names start with a
  letter or digit.
- The gate sets its own `PATH`, refuses to run on a malformed protect setting, and tolerates an empty list on bash 3.2.
- A configuration file that is not valid JSON is reported without quoting the parser's message.
- The hygiene check reports binary and oversized files instead of skipping them, can scan every line ever committed (`--history-content`), and treats `prepack`
  as an install-time script; the pack check requires the two server-side scripts to stay executable.
- Documentation: one account name (`deploy`) throughout, a Claude Code `permissions.deny` example for the state directory with its limits, the failed-secret
  file name, the inventory's list values.

## Round 2: a second look at the fixed code

Three new reviewers, with no knowledge of round 1 or of its findings, read the code as it stood after the round 1 fixes: (1) injection, validation, quoting and the
generated gate; (2) approval, authorisation and state; (3) secrets, local files, output handling, supply chain and CI. None found a high-severity issue. The
approval reviewer found no way to run a changing command without a human's accepted answer (or, for writes, the documented `approval.write: "client"`), and no way to
forge, replay or reuse a plan token; the injection reviewer found no way to put an unvalidated option, value or shell word on a command line; the secrets reviewer found
no way to read a generated password from the files or the tools (the one path they found needs hostile server output, and is fixed below). Together they found three
medium issues and a number of low and informational ones. All of them are fixed or documented below.

### Medium

| Finding | Fix | Test |
| ------- | --- | ---- |
| **Two profiles could share one SSH connection.** ssh names a shared connection by host, port and user, not by key. A profile with a read-only key behind a strict gate, and another with a laxer key, would send their commands over whichever connection was opened first. | The socket directory is per login: `<state>/cm/<hash of alias, user, port, identity file and configuration file>/`. | `test/ssh.test.ts`; mutants `ssh-socket-*`. |
| **A file directory could be in a place other accounts write.** `/home/shop/...` or `/tmp/...` passed validation. `clpctl` runs as root and follows symbolic links, so a link planted by a hacked site's user would turn a dump into the overwrite of any file, and a certificate or template into the read of any file. | `/home`, `/tmp`, `/var/tmp`, `/var/www`, `/var/mail`, `/mnt` and `/media` are refused (with the system directories already refused), unless `allowUntrustedFileDirs` is set, which exists for throw-away test servers and adds a warning. The README says that every file directory must be root-owned, and why. | `test/config.test.ts`, `test/cli.test.ts`; mutants `config-shared-*`, `config-untrusted-*`, `warning-untrusted-*`. |
| **In the 2026 protocol era several approval questions could be open at once for one profile.** Nothing waits inside the server there, so the "one question at a time" flag lasted a single tick. | The server remembers the question it put: one open question per profile for ten minutes, each with a fresh nonce in the key the client must echo. A second, different question is refused while one is open; an answer closes its question and is used once; an answer given to an earlier question (cached or re-sent by a client) carries an old nonce and approves nothing. A new question is audited as `asked`. | `test/hardening.test.ts` ("approval questions in the 2026 era"); mutants `engine-question-*`. |

### Low and informational

Fixed, each with a test unless it is a documentation change:

- **A generated password could survive redaction** if invisible characters or escape sequences were inserted into it: the redactor searched first, the cleaning removed the
  inserted characters afterwards and put the password back together. Redaction now cleans first (`Redactor.scrub` removes escape sequences and invisible characters before it
  searches), everywhere server text is turned into something the model sees. The `--...password...=value` scrubber no longer shifts positions for letters that change
  length when lower-cased, takes quoted values with spaces, accepts `--password = value` and redacts the rest of the line after a quote that never closes.
- **Seven invisible code points passed the cleaning** (the Hangul and Khmer fillers, the combining grapheme joiner, ...): every default-ignorable code point is now removed
  (a test scans the whole code space). **The hygiene check missed tag characters** ("ASCII smuggling" in documents that ship in the package) and the same code points: it
  now uses the same classes.
- **The release workflow** now has three jobs: one that runs the dev dependencies and the tests and publishes nothing, one on a fresh runner that compiles with scripts off
  and records the tarball's checksum, and the one that publishes, which checks the checksum, the file list against the allowlist of `scripts/check-pack.mjs`, that
  the package has no install-time script, exactly the two dependencies at exact versions and the expected `bin`, and the version. Its check is run in the tests on real
  and tampered tarballs. One residual: the compiler is part of the build, and provenance attests the workflow, not the compiler's honesty.
- **`clp_list_commands` and the inventory** put names and values chosen by the server at the top level of the result and without a size bound. They are now inside
  `output`, labelled and capped (300 command names; 60,000 characters of inventory).
- **Domain protection ignored one `www.` only**, so `www.www.example.com` (whose "other form" is the protected `www.example.com`) was not protected; the server and the gate
  now ignore every leading `www.`.
- **Database user names had no reserved list**: `root`, `mysql`, `clp`, `debian_sys_maint` and the other system accounts are refused, on the server and in the gate.
- **The gate accepted protect settings that protect nothing** (a domain with a trailing dot, a single-label host, an underscore); each list is now checked against the
  pattern of its kind, as the server's configuration is. A **site-user gate ignored `PROTECT_SITE_USERS`** because its commands carry no user name; it now compares the
  account it runs as.
- **The plan token is checked again after the human decided**, so a human who takes longer than the token's ten minutes gets a refusal; **used tokens are remembered whatever
  the clock does** (oldest dropped first beyond 10,000) instead of being expired by it.
- **Reads, the inventory and forced re-detections** could be fired without limit; reads now run at most four at a time per profile, and a forced re-detection answers from the
  cache within 30 seconds of the last probe.
- **The audit log**: successful reads are recorded (the README said every call was); refusals, dry runs and reads are written at most 120 a minute each, with a note when the
  rest are counted instead; the name of an unknown tool is written as short printable text.
- **The inventory script** refuses a backslash in the values that a bracket expression admits on some awk implementations (busybox). No test on another awk can see this guard,
  so its mutant is documented as equivalent.
- **Documentation**: a dump taken from a database an attacker influences is attacker-controlled SQL when imported elsewhere (import only dumps you trust).

## Round 3: a look at the round 2 fixes

Two more fresh reviewers read the code changed since round 2 (the question state, the token, the redactor, the audit log; the gate, the transport, the configuration, the
release workflow). They found two medium issues in the new code and a number of low ones; all are fixed.

| Finding | Fix |
| ------- | --- |
| **Medium: in the 2026 era one approval could run a write twice.** Two identical calls re-sent at once both read the open question before either closed it (the close came after an `await`). | The branch that reads, claims and opens a question no longer awaits anything (`ClientIO.answerFor` is synchronous), so one answer is used by one call and one question is opened by one call. Tested with calls re-sent at the same moment. |
| **Medium: the audit log could be flooded with `approval:unsupported` records** by a client that cannot show forms. | Throttled like refusals. |
| **A flood of one kind of refusal could hide another** (a protected-domain or forged-token refusal among 130 invalid-argument ones). | The throttle is per kind of reason (invalid, class, protected, token, rate, ...). |
| A question stayed open after a late re-send was refused; repeated identical calls showed the human the form again for free. | A question does not outlive its plan token; every time the human is shown a question counts against `rateLimits.ask`. |
| Redaction: a password in escaped quotes (`\"...\"`) or with a quote inside leaked; the server's JSON message was not scrubbed after decoding; inventory values were cut before they were scrubbed. | The scrubber handles escaped quotes and takes unquoted values to the next space; decoded text is scrubbed again; values are scrubbed whole, then cut. |
| 50 parallel forced re-detections made 50 probes; the semaphore let a new caller slip in ahead of a waiter. | Callers share one probe; the finished job hands its place to the next waiter. |
| **The gate checked only the PROTECT lists**: `ALLOWED_FILE_DIRS=(/tmp)`, a malformed `PROXY_HOSTS` or `APP_PORTS` were accepted. A site-user gate installed for root or a system account ran as that account. | The gate refuses to run with a directory in a system or shared place (same lists as the server, generated), with a bad proxy host or port entry (a single port the server never allows included), and a site-user gate refuses root and system accounts. |
| The shared-directory rule missed `/var/lock`, `/var/crash`, `/var/spool`, `/var/lib/php`, `/var/run`; the default port ranges contained unauthenticated admin APIs (Nomad 4646, `kubectl proxy` 8001, InfluxDB 8086, ...). | Added to the lists; the denied ports now include them (and RDP, Subversion, Salt, Vault, Consul, Prometheus, node exporter, kubelet). |
| A site user's ssh login could name another account (root). A shared ssh connection outlived a replaced or revoked key by up to a minute. | The login must be the site user; connections linger 15 seconds and a replaced key file gets a new connection. |
| **Release setup**: the workflow's branch condition protects nothing against someone who can push a branch; a repository-level token would be readable by any workflow. | [docs/RELEASING.md](RELEASING.md) and the workflow header say how to set it up (environment secret, deployment branches, reviewers, or trusted publishing). |

### Left as it is, on purpose

- **A file directory cannot be checked for ownership from here.** The server refuses the places other accounts usually write; whether every component of the path is root-owned is
  the operator's to ensure (stated in the README).
- **The audit log can still be filled slowly**, and a full disk makes every changing tool refuse. That fails closed.
- **A backwards step of the OS clock** shortens or extends a token's life; it no longer revives a used token. Controlling the clock is outside the threat model.
- **The compiler is trusted.** The build job runs TypeScript; a compromised compiler could produce a malicious `dist/`. The checksum and the publish-time checks catch tampering
  after the build, not before it.

## Round 4: a look at the fixes made during the live tests

One more fresh reviewer read everything changed since round 2, including the fixes that the tests against a real CloudPanel had led to. It found one medium
issue and six low ones; all are fixed, each with a test and, where the fix is a guard, a mutant.

| Finding | Fix |
| ------- | --- |
| **Medium: a deletion could be reported that never happened.** `clpctl` puts some yes/no questions to a terminal, and there is none. `user:delete` had been seen to end such a question with exit status 0 and nothing done, and only that one tool checked for it; `db:delete` asks the same kind of question, and no live run had checked its effect. | The rule is now the engine's, for every changing tool: a command whose output shows an unanswered `(yes/no)` is reported as **not confirmed** (`ok: false`, `unconfirmed: true`) unless the command itself then says it has done the work (`db:delete`: "The database X has been deleted"). The live contract test now checks the effect of `db:delete` (the name can be used again). |
| The scrubber took an unquoted password value up to the next space, so a JSON error line that ended in a generated password was cut and no longer seen as an error (exit status 0 was then a success); a second pass over a command line ate the closing quote after `[REDACTED]`. | The error line is read from the output as the server wrote it, and its message scrubbed whole before it is cut. A value that is already the placeholder is left alone when a closing quote, a space or the end follows it. An unknown value is still taken up to the next space. |
| In the 2026 era the answer was claimed and the plan token used up on two sides of an `await`: a duplicate of an approved call could slip between them, open a second question for the used token that nobody could answer, and block the profile's changing tools until the token lapsed. (The command still ran once.) | The token is checked again and used up in the same synchronous step that takes the answer, in both eras; the duplicate is refused as already used and no question stays open. |
| The gate split the list of a protected option with a here-string and did not check that it worked; had the shell been unable to create it, the check would have seen no entries. | The list is split with parameter expansion only. |
| Audit log: the count of records held back was written only when another record of the same kind came, and was dated one minute off; a human's decision left no record when the token had lapsed meanwhile; `clp_server_info`, `clp_list_commands` and `clp_inventory_sites` left no record. The bound is per kind of record, so a model that varies the kind can cause about twenty times 120 records a minute, not 120. | The count is written with the next record of any kind and at shutdown, under the right minute; the decision is recorded first; those three reads are recorded. The README and the specification now state the real bound. |
| The scrubber took the column separator of a table for the value of a name ending in `--password`, which shifted the cells of `user:list`. | A lone `\|` is not a value; the table is read from the output as the server wrote it and each cell is scrubbed. |
| Hygiene: beside a GitHub noreply address, the free-text name was not checked against the private patterns; GitHub's own committer identity (a merge made on the website) was refused. | The name is exempt only when it is the login in the address; GitHub's own identity (the name `GitHub` with its own `noreply` address) is accepted as a committer, never as an author. |

Still open after round 4, and stated in the README: the effect of `db:import`, `user:reset:password` and `user:disable:mfa` has been checked only by exit status
against a real server, and the wording of `db:delete`'s success line comes from an earlier recording, so a real CloudPanel may make that tool answer "not
confirmed" until the next live run settles it. Both err on the safe side.

## Not fixed on purpose

- **"Accept" proves only that the client said so.** A client that auto-approves, or a person who clicks through, defeats the approval. See "Honest limits" in the
  README. The server can make the question precise and hard to wear down (a typed name, a limit on questions); it cannot make a person read it.
- **Anything running as your own OS user can do what the server can.** The state directory and the configuration are private to you, not to a process that
  runs as you.
- **A password is a command-line argument** because `clpctl` takes it that way.
- **The gate limits the shape of what a key may run**, not whether it should.

## Reporting

Please report a weakness privately; see [SECURITY.md](../SECURITY.md).
