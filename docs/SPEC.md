# Specification

Status: draft (2026-11-05). The project is **cloudpanel-mcp-server** (decided 2026-11-05, see §12).
Facts about `clpctl` come from [COMMAND-REFERENCE.md](COMMAND-REFERENCE.md); choices are recorded in [adr/](adr/).

## 1. Purpose and non-goals

An MCP server (stdio) that lets an AI assistant administer one or several **CloudPanel v2** servers through the vendor's own CLI, `clpctl`,
with a human in the loop for anything that changes or destroys something.

Non-goals, stated so nobody expects them:

- No raw command tool, no shell, no file upload, no installer, no edits to other tools' configuration.
- No scraping of the web UI, no writes to CloudPanel's private database or NGINX files. The CLI is the only way to change anything.
- No tool for things the CLI cannot do (WordPress sites, PHP settings, cron, firewall, ...; list in COMMAND-REFERENCE §5). They are named in the
  documentation, not improvised.
- Not a defence against a compromised workstation or against a model that has its own shell on the same machine ([§3](#3-threat-model)).

## 2. Architecture

```
MCP client (Claude Code, Claude Desktop, Cursor, VS Code, ...)
        │  stdio, JSON-RPC            ← the only thing the model can reach
        ▼
cloudpanel-mcp-server  (Node ≥ 22, @modelcontextprotocol/server 2.x, zod)
  config ─ profiles, operator gates, approval policy, protected targets
  catalog ─ typed tools: schema, class, annotations, plan builder
  policy ─ class gate · availability (probe) · protected targets · rate limit · plan token · approval
  executor ─ argv builder → quoting → transport → result parser → redaction → audit
  secrets ─ generated passwords → mode-0600 files, never in a result
        │  system OpenSSH (alias or user/host/port/key)   or   direct exec on the CloudPanel host
        ▼
CloudPanel host:  [sudo -n] /usr/bin/clpctl <command> '--name=value' ...
        ▲
        └─ optional: forced-command gate (generated, hardened mode) · optional read-only inventory script (unofficial)
```

One process, one stdio connection, any number of **profiles** (named servers). Source layout and module boundaries are in the repository
(`src/`); the catalogue is the single source of truth for the tool list, the generated tool reference in the README, the hardened-mode gate and the
simulator's argument grammar.

SDK: `@modelcontextprotocol/server` 2.x with `serveStdio` ([ADR-0001](adr/0001-mcp-sdk.md)). Runtime dependencies: that package, its `core`, and
`zod`; all exact-pinned, no install scripts.

## 3. Threat model

**Assets:** the CloudPanel server (sites, databases, users, certificates, the panel itself); the SSH identity used to reach it; generated passwords;
the audit log.

**Adversaries and what we do about them**

| Adversary | Example | Defence | Residual risk |
| --------- | ------- | ------- | ------------- |
| Prompt injection into the model | a web page, a log line, a `clpctl` error, a site file tells the model to delete a site | read-only by default; classes switched on by the operator; a **human approval outside the model's reach** for destructive/admin actions; static tool descriptions; every output labelled untrusted and stripped of control sequences | the human approves something they did not read; a client or hook that auto-accepts |
| A confused or over-eager model | wrong domain, wrong profile, repeats a call | strict validation; dry-run plan; protected targets; rate limits; the approval text names profile, command and target | – |
| Hostile values in arguments | shell metacharacters, option injection (`--force`), path traversal, ANSI escapes | strict allow-list patterns, `--name=value` tokens, quoting, no shell locally, paths confined to operator-chosen directories | a bug in a pattern (mitigated by property tests, a mutation harness and an adversarial review) |
| Someone who steals the SSH key | uses the key by hand | optional **forced-command gate** limits the key to the same grammar and class ceiling as this server | without the gate, the key is as powerful as its sudoers rule |
| Another process of the same OS user | edits the config or audit log, reads password files | file modes 0600/0700; config read once at start | **not defended**: same-user code can do anything this server can ([§4.8](#48-honest-limits)) |
| A malicious or compromised `clpctl` output | text steering the model | output is data: sanitised, bounded, labelled | the model may still read it |
| Supply chain | a hijacked dependency or release | 3 runtime packages, exact pins, lockfile, no install scripts, npm provenance, CI audit, Dependabot, no committed build output | the usual |

**Out of scope:** the security of CloudPanel itself (keep it updated: its changelog lists privilege-escalation fixes up to v2.5.0), of the server's OS,
of the MCP client.

## 4. Safety model

### 4.1 Classes

| Class | Meaning | Examples | Enabled by |
| ----- | ------- | -------- | ---------- |
| READ | changes nothing | list users, list templates, view a template, server info | always |
| WRITE | creates or updates, never removes | add a site, a database, a certificate, a template | `allow: ["write"]` |
| DESTRUCTIVE | removes or overwrites data, not undoable | delete a site or a database, import a dump, delete a template | `allow: ["destructive"]` |
| ADMIN | changes who can get into the panel | add/delete a panel user, reset a password, disable MFA, panel Basic Auth, release channel, master credentials | `allow: ["admin"]` |

The classes are independent (`destructive` does not imply `write`). A tool whose class the profile does not allow is **not listed** and a forced call is
refused again at execution; both are tested. With no configuration only the READ tools exist.

### 4.2 Pipeline for every call

1. Class gate (profile) → 2. strict argument validation (unknown keys refused) → 3. cross-field rules → 4. protected targets → 5. availability (the
`clpctl` on that profile has the command and its required options, [§8.4](#84-feature-detection)) → 6. rate limit → 7. plan / dry run → 8. approval →
9. audit `start` → 10. run → 11. parse, redact, bound → 12. audit `end` → 13. result.

Any step that fails returns a refusal (`isError`) with a reason that never echoes a secret; the refusal is audited.

### 4.3 Dry run and plan token

Every changing tool takes `dryRun` and `planToken`. A dry run runs nothing and returns the **plan**: tool, profile, class, the exact redacted command, a
plain-language list of effects, whether it can be undone, and which approval it will need. For DESTRUCTIVE and ADMIN tools a call without a valid
`planToken` is treated as a dry run and returns the token; the real call must carry it.

The token is an HMAC (key random per process) over tool, profile and a canonical form of the arguments, with an expiry (10 minutes) and a nonce that
is consumed on use. A token for another target, another profile or another set of arguments is useless. The token stops accidents and replays, not a
model that is willing to call both steps: the approval is what stops that ([§4.4](#44-human-approval)).

### 4.4 Human approval

Rules (ADR-0002):

- **Who approves:** a human, through the MCP client, by **elicitation** (form mode). The question is built by the server from validated state: profile,
  class, the exact command, the effects, the target. The model supplies nothing that appears in the question except the already-validated arguments.
- **What counts as approval:** an explicit `accept` whose form content is valid. For DESTRUCTIVE and ADMIN the human must **type the target's name**
  (domain, database, user, template) and it must equal the target; for WRITE the human ticks a box that must be `true` (a checkbox can be submitted
  unticked). Anything else refuses: decline, cancel, timeout, an error, a mismatch, an unsupported client.
- **No elicitation in the client:** fail closed. The tool refuses and returns the **exact command** (passwords as placeholders) so the human can run it
  in their own terminal. Nothing is run.
- **Never a model-supplied string.** There is no `confirm` parameter that the model can fill in to make a destructive call go through.
- **A second gate in Claude Code:** DESTRUCTIVE and ADMIN tools carry `_meta["anthropic/requiresUserInteraction"] = true`. Claude Code then asks for
  every call, ignores allow rules and "don't ask again", prompts even in auto and bypass modes, and denies in `dontAsk`
  (<https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool>, read 2026-11-05).
- **Annotations are set correctly** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint: false`) but are hints only.
- **WRITE policy:** `approval.write` is `"ask"` (default: elicitation as above) or `"client"` (the operator states that their client already asks for
  every non-read-only tool call; no extra form). DESTRUCTIVE and ADMIN have **no** off switch.
- **The decision is always audited** (`accept`, `decline`, `cancel`, `timeout`, `unsupported`, `mismatch`, `error`), before anything runs.
- **Both protocol eras:** the approval is written once as an "input required" step; the SDK serves clients of the 2025 era (a pushed
  `elicitation/create`) and of the 2026-07-28 era (a retried call carrying the answers) from the same handler. Approval keys are bound to the call
  (tool, profile, arguments, and for DESTRUCTIVE and ADMIN the plan token), so an answer cannot be replayed for another call.
- **The 2026 era keeps its own state.** A call there is re-run with the answer, so nothing waits inside the server. The server therefore remembers the
  question it put: at most one open question per profile, for ten minutes, each with a fresh random nonce in the key the client must echo. A second,
  different question is refused while one is open (the same call asked again is the same question, not a new one); an answer is used once and closes its
  question; an answer given to an earlier question, cached or re-sent by a client, carries the earlier nonce and approves nothing. A new question is audited
  as `asked`. In the 2025 era the question is a request that blocks the call, and a per-profile flag keeps a second one from being put meanwhile.
- **The plan token is checked again after the human has decided**, not only before: a human who takes longer than the token's ten minutes gets a refusal, not a
  command that runs on a token that lapsed.

README gives users the matching client-side rules: Claude Code `permissions.ask` globs, VS Code's manual-approval setting, and what to do with clients
that cannot show a form.

### 4.5 Protected targets

Configured per profile: domains (exact or `*.suffix`, a leading `www.` ignored), site users, databases, panel users. A protected target can never be **the
target of a changing tool** that names it: not deleted, overwritten or reset, and also not given a certificate or a database, not exported, not created again
under that name (a new site below a protected wildcard is refused). The rule is uniform: every changing tool that takes a domain, a site user, a database or a
panel user checks the matching list, and a test enforces that no tool is missed. Names other than domains are compared without regard to case. Built-in
reserved names are always unusable (`root`, `clp`, `mysql`, `sys`, `information_schema`, `performance_schema`, the panel's own database `clp`, ...).

**What it does not cover.** The server cannot see what a site owns. `site:delete` removes the site's files, **its site user and its databases** with it, so
`protect.siteUsers` and `protect.databases` do not protect a site from being deleted by its domain: protect the domain. `clp_server_info` and `--check-config`
show the lists and warn about this and about destructive tools with no protected domain. The documentation tells operators to list the panel's own domain
and their production sites.

### 4.5a Files and ports

Each kind of file has its own subdirectory of a file directory and its own extensions: dumps in `<dir>/dumps/` (`*.sql`, `*.sql.gz`), certificates in
`<dir>/certs/` (`*.key`, `*.pem`, `*.crt`, `*.cer`, `*.cert`, `*.chain`, `*.ca-bundle`), vhost templates in `<dir>/templates/` (`*.tpl`, `*.conf`). Only the
operator puts files into `certs/` and `templates/`; the tools can write only into `dumps/`. So a file one tool writes can never be read by another as
something else (a dump cannot become a vhost template or a certificate), which cuts the chain "export a database, then install it as NGINX configuration".
`db:export` and `db:import` refuse the system databases and the panel's own database.

Application ports (Node.js and Python sites, reverse-proxy upstreams besides 80 and 443) must be in the profile's `appPorts` (default 1337, 2368, 3000-4999,
5000, 5173, 8000-8199). Above that sits a hard floor that no setting lifts: ports below 1024 and the ports of databases, caches, queues, container and admin
APIs, the panel and Varnish (the list is `DENIED_APP_PORTS` in `src/validate/patterns.ts`; it includes 3306, 5432, 6379, 8443, 9200, 11211, 27017 and the unauthenticated
administration APIs of Docker, etcd, Kubernetes, Nomad, Vault, Consul, InfluxDB, Prometheus and others).

### 4.6 Rate limits

A sliding window per profile and class (defaults: WRITE 20 per 10 min, DESTRUCTIVE 3 per 10 min, ADMIN 5 per 10 min; configurable, never unlimited for
DESTRUCTIVE and ADMIN). Dry runs and reads are not counted. Changing commands run one at a time per profile; reads run at most four at a time (each is an ssh
session and a `clpctl` run on the host), and a forced re-detection (`clp_list_commands` with `refresh`) answers from the cache within 30 seconds of the last
probe. A fourth window, `ask` (default 30 per 10 min),
limits the approval questions put to the human, whether answered yes or no, and only one question per profile waits at a time: a model that is declined
cannot turn the approval form into a way to wear a person down. In the 2026 protocol era, where a call is re-run with the answer, a question counts once.

### 4.7 Audit log

`<state>/audit.jsonl`, mode 0600, append-only JSON lines: `time`, `profile`, `event` (`start`, `end`, `refused`, `plan`, `approval`, `note`), `tool`, `class`,
the redacted command, exit code, duration, the decision (`asked`, `accept`, `decline`, ...) and its reason, secret-file paths (never contents). Reads are
recorded too. If an audit line that precedes a changing call (its approval, its start) cannot be written, the command is not run. The records a model can cause at
will (refusals, dry runs, reads) are written at most 120 a minute per kind of record (a refusal's kind includes its class and the kind of its reason, about twenty in all); a `note` line says when the rest are being counted instead, and how many there were: with the next record of any kind, and at shutdown.
The records that matter are never held back. Strings are cleaned of escape sequences and invisible characters before they are written.

### 4.8 Honest limits

- "Accept" proves only that **the client said so**. Hooks, bypass modes, SDK callbacks and scripts can auto-accept; a UI can fail to render.
- Annotations and metadata are **hints** that a client may ignore.
- Anything running as the same OS user (including a model with a shell tool) can read the audit log, the password files and the SSH key, edit the
  configuration, or call `ssh` directly. File permissions and approvals are not a barrier against it.
- A file directory must be root-owned on the server. The server checks it lexically only (it refuses `/home`, `/tmp`, `/var/tmp`, `/var/www`, `/var/mail`,
  `/mnt`, `/media` and the system directories unless `allowUntrustedFileDirs` is set); whether another account can write in it is the operator's to ensure.
- `clp_db_import` runs a dump as SQL. A dump taken from a database that an attacker influences is attacker-controlled when imported elsewhere.
- A password given to `clpctl` is a command-line argument: `sudo` logs it and `ps` shows it while the command runs, on the server and on the machine
  that runs `ssh`. The generated password is a first-login password; change it.
- The server cannot know which domain is "production". Protected targets only protect what the operator lists.
- `clpctl` itself is the authority on what is valid; this server's patterns are conservative, not complete.

## 5. Tool catalogue

### 5.1 Conventions

- Names `clp_<command with : and - as _>`; static descriptions written for the model: what it does, which approval it triggers, that output is untrusted.
- Parameters: `profile` (required when more than one profile exists), the command's options, and for changing tools `dryRun`, `planToken`.
- Passwords are **never parameters** ([§6](#6-secrets)); a call that tries is refused.
- Version values (`phpVersion`, `nodejsVersion`, `pythonVersion`) are checked by **shape** (`8.4`, `22`, `3.12`), not by a list; CloudPanel's refusal is
  returned ([ADR-0004](adr/0004-feature-detection-and-version-shapes.md)).
- Result: one JSON text block: `ok`, `profile`, `tool`, `command` (redacted), `exitCode`, `secretsFile`, `timedOut`, `note`, and `error` (this server's own
  error, never text from the server), plus `output`, the one object that holds what came from the server: `untrusted` (a label), `stdout`, `stderr`
  (sanitised, bounded), `table` (for the two listings) and `serverMessage` (the message of `clpctl`'s JSON log line when the call failed). When a command's
  output holds secrets (`db:show:master-credentials`) `stdout` and `stderr` read "not shown", also when the call fails.
- A call is a success when the exit status is 0, the output holds no JSON log line of level ERROR or worse (looked for in the output as the server wrote it),
  and, for a changing tool, no yes/no question of `clpctl` was left unanswered. There is no terminal to answer one, and a command was seen to end such a
  question with exit status 0 and nothing done; the result is then `ok: false` with `unconfirmed: true`, unless the command itself goes on to say that it has
  done the work (`db:delete`).

### 5.2 READ

| Tool | Runs | Notes |
| ---- | ---- | ----- |
| `clp_server_info` | `clpctl` (usage listing), cached | profile, allowed classes, protected targets, whether this client can approve, detected commands, tool availability, `clpctl` version if the listing shows it |
| `clp_list_commands` | `clpctl` | commands and options on the server, compared with the documented set; "not wrapped" commands are listed, never callable |
| `clp_user_list` | `user:list` | |
| `clp_vhost_templates_list` | `vhost-templates:list` | |
| `clp_vhost_template_view` | `vhost-template:view --name` | |
| `clp_inventory_sites` | optional companion (unofficial) | only if the profile enables it ([ADR-0003](adr/0003-optional-inventory.md)) |

### 5.3 WRITE (approval: tick-box, or the client's own with `approval.write: "client"`)

| Tool | Runs | Notes |
| ---- | ---- | ----- |
| `clp_site_add_php` | `site:add:php` | `vhostTemplate` as `vhost-templates:list` shows it |
| `clp_site_add_nodejs` | `site:add:nodejs` | `appPort` must be in the profile's `appPorts` |
| `clp_site_add_python` | `site:add:python` | `appPort` must be in the profile's `appPorts` |
| `clp_site_add_static` | `site:add:static` | |
| `clp_site_add_reverse_proxy` | `site:add:reverse-proxy` | upstream host must be in the profile's `proxyHosts` (default loopback), port 80, 443 or in `appPorts` |
| `clp_lets_encrypt_install_certificate` | `lets-encrypt:install:certificate` | needs DNS pointing at the server; 600 s timeout |
| `clp_site_install_certificate` | `site:install:certificate` | key/certificate/chain are files the operator put in `<fileDirs>/certs/` |
| `clp_db_add` | `db:add` | |
| `clp_db_export` | `db:export` | writes a dump into `<fileDirs>/dumps/`; an existing file is overwritten, so the plan says so; not for system databases |
| `clp_vhost_template_add` | `vhost-template:add` | a file the operator put in `<fileDirs>/templates/`; remote URLs are not accepted |
| `clp_vhost_templates_import` | `vhost-templates:import` | |
| `clp_cloudflare_update_ips` | `cloudflare:update:ips` | |

### 5.4 Site-user tools (WRITE)

`system:permissions:reset` and `varnish-cache:purge` are documented as **site-user** commands. Running the first as root with a chosen path is
undocumented and could follow symlinks, so these two run **as the site user**: the profile's `siteUserAccess` maps a site user to an SSH alias that
logs in as that user (the operator sets up the key in the panel). A tool refuses with an explanation when the site user has no entry.
`clp_system_permissions_reset` takes `siteUser`, `directories`/`files` modes (octal, `0[0-7]{3}` shape) and a relative `path` below the home directory;
`clp_varnish_cache_purge` takes `siteUser` and a `purge` of `all`, a tag list or one URL of that site's domain.

### 5.5 DESTRUCTIVE (approval: type the target's name; plan token required)

| Tool | Runs | Confirmation target |
| ---- | ---- | ------------------- |
| `clp_site_delete` | `site:delete --force` | the domain; the plan states that files, databases, users and configuration go |
| `clp_db_import` | `db:import` | the database name; overwrites data |
| `clp_db_delete` | `db:delete` | the database name; observed-only command |
| `clp_vhost_template_delete` | `vhost-template:delete` | the template name |

### 5.6 ADMIN (approval: type the target's name; plan token required)

| Tool | Runs | Notes |
| ---- | ---- | ----- |
| `clp_user_add` | `user:add` | generated password; role `admin|site-manager|user`; `sites` only for `user` |
| `clp_user_delete` | `user:delete` | confirmation target: the user name |
| `clp_user_reset_password` | `user:reset:password` | generated password |
| `clp_user_disable_mfa` | `user:disable:mfa` | lowers an account's security |
| `clp_cloudpanel_enable_basic_auth` | `cloudpanel:enable:basic-auth` | the **panel**, not a site; generated password |
| `clp_cloudpanel_disable_basic_auth` | `cloudpanel:disable:basic-auth` | |
| `clp_cloudpanel_set_release_channel` | `cloudpanel:set:release-channel` | sets the channel only, never runs `clp-update` |
| `clp_db_show_master_credentials` | `db:show:master-credentials` | the password is written to a 0600 file, never returned; host, user and port are |

The tool list is static per process. Tools of classes a profile does not allow are not listed (a profile set is fixed at start).

## 6. Secrets

- Passwords are generated by the server (32 characters from `[A-Za-z0-9]`, uniform), written to
  `<state>/secrets/<profile>/<kind>-<target>-<time>-<rand>.json` (directory 0700, file 0600, exclusive create) **before** the command runs, and only the
  path is returned. A failed command renames the file to `*.failed.json` (the password was probably never applied). The output of a command that prints a
  secret (`db:show:master-credentials`) is saved the same way, whole, and is never returned, also when the call fails.
- No tool takes a password; the redactor removes any generated password and any `--*password*=value` from every result, error and audit line.
- Windows has no POSIX modes: the files inherit the user profile's ACL; this is documented.
- Form elicitation is never used to ask for or show a secret.

## 7. Configuration

Read once at start. Two equivalent forms:

- a JSON file (`CLOUDPANEL_MCP_CONFIG`, default `<config dir>/config.json`) with `profiles` and `defaultProfile`;
- environment variables for a one-profile quick start (`CLOUDPANEL_MCP_SSH_HOST`, `CLOUDPANEL_MCP_ALLOW`, ...).

```jsonc
{
  "profiles": {
    "my-server": {
      "ssh": { "host": "my-server", "user": "deploy", "port": 22, "identityFile": "~/.ssh/id_ed25519" },   // or "local": true
      "elevation": "sudo",                    // "sudo" (default) or "none" (root, or already privileged)
      "clpctlPath": "/usr/bin/clpctl",
      "allow": ["write"],                     // READ is always on; add "destructive", "admin" deliberately
      "approval": { "write": "ask" },
      "protect": { "domains": ["panel.example.com", "*.shop.example.com"], "siteUsers": [], "databases": [], "panelUsers": ["owner"] },
      "fileDirs": ["/var/lib/cloudpanel-mcp-server"],   // its subdirectories dumps/, certs/, templates/
      "proxyHosts": ["127.0.0.1", "localhost", "::1"],
      "appPorts": [1337, 2368, "3000-4999", 5000, 5173, "8000-8199"],
      "siteUserAccess": { "shop": "my-server-shop" },
      "inventory": false,
      "rateLimits": { "write": [20, 10], "destructive": [3, 10], "admin": [5, 10], "ask": [30, 10] },
      "timeoutsSeconds": { "default": 120, "letsEncrypt": 600, "db": 600 }
    }
  },
  "defaultProfile": "my-server"
}
```

Validation is strict and fails closed at start (exit 2 with a message on stderr): unknown keys, bad values, a profile with no way to reach a host,
paths that are not clean absolute paths. State lives in `<state>` (`$XDG_STATE_HOME/cloudpanel-mcp-server`, default `~/.local/state/cloudpanel-mcp-server`; `~/Library/Application Support/cloudpanel-mcp-server` on macOS,
`%LOCALAPPDATA%\cloudpanel-mcp-server` on Windows; overridable), mode 0700.

## 8. Execution

### 8.1 Transports

- **SSH:** the system `ssh`, spawned without a local shell, stdin closed: `-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes`
  (`-p`, `-l`, `-i` from the profile when set), connection sharing (`ControlMaster=auto`, short `ControlPath`, `ControlPersist=60`) on platforms that
  support it (not Windows). ssh names a shared connection by local host, remote host, port and user, **not by key**, so the socket directory is
  `<state>/cm/<key>/` where `<key>` is a hash of the alias, user, port, identity file and configuration file of the target: two profiles that differ only in
  the key (a read-only key behind a strict gate and a write key behind a lax one) never share a connection. The directories are created privately (0700)
  before the first use; where that fails, or the path is too long or holds characters ssh would expand, sharing is switched off.
  Host values are validated and can never start with `-`; `--` precedes the remote command.
- **Local** (`"local": true`): run the same argv directly with `execFile` on the CloudPanel host (the MCP client can reach it through
  `ssh host cloudpanel-mcp-server`); no shell at all.
- Site-user tools use a separate SSH target per site user (§5.4).

### 8.2 Quoting

Values are checked by strict patterns that exclude every shell metacharacter and quote, then every token is single-quoted anyway, and every option
is a single `--name=value` token, so a value cannot become an option. The patterns are written to mean the same in JavaScript and in POSIX extended
regular expressions, so the same text drives the hardened-mode gate.

### 8.3 Output

stdout and stderr are captured with a hard byte cap, scrubbed of generated secrets, stripped of ANSI and control characters, truncated, and returned
inside fields labelled untrusted. The `message` of `clpctl`'s JSON log line becomes `output.serverMessage`. A timeout kills the local `ssh`; the result says the
command may still be running on the server.

### 8.4 Feature detection

On first use of a profile (and on `clp_server_info {refresh: true}`) the server runs `clpctl` with no arguments and parses the usage listing into
commands and the options shown on each line. A tool is **unavailable** (refused with a clear message) when its command is absent or a **required**
option is not shown; optional options are never judged by the listing, because it may omit them. If the listing cannot be parsed the server says so,
treats detection as unknown and relies on `clpctl`'s own answer. Commands on the server that no tool wraps are reported by `clp_list_commands` and
never executable.

## 9. Hardened mode and the optional inventory

- **Gate:** a bash forced-command script for `authorized_keys`, **generated from the catalogue** (`npm run gen:gate`; a test fails if the committed
  copy drifts). It accepts only `sudo -n <clpctl> <command> '--name=value' ...` for known commands, options and value shapes, with class ceilings
  (`ALLOW_WRITE/DESTRUCTIVE/ADMIN`), the file directories (with the `dumps/`, `certs/`, `templates/` subdirectories), application ports, proxy hosts and
  protected targets, and never re-parses arguments through a shell. It sets its own `PATH`. It limits the *shape* of what a key may run, not the intent: with the
  write ceiling a stolen key can still create a site user with a password of its choosing (README, "What the gate cannot do"). The tests run one corpus through the
  TypeScript validators and through the real script. Nothing applies it for the user; README lists the commands.
- **Inventory:** [ADR-0003](adr/0003-optional-inventory.md). Optional, unofficial, read-only, installed by the server's operator as root with its own sudoers
  line, no arguments. Its output is data: only keys of letters, digits and `_`, and values that are strings, numbers, booleans or lists of strings (such as
  `aliases`) are kept, bounded and cleaned like any output of the server.

## 10. Test strategy

| Layer | What | How |
| ----- | ---- | --- |
| Unit | validators, quoting, config, redaction, secrets, audit, rate limiter, plan token, approval state machine, output sanitiser, usage and error parsers | `node:test`, TypeScript run directly |
| Property / fuzz | every pattern against hostile generators; quoting through real `/bin/sh` and `bash`; parsers never throw; random JSON arguments never reach the runner unless valid | `fast-check` (dev only), plus seeded corpora |
| Simulator | `clpctl` stand-in with the documented and observed grammar: strict options, validation messages, JSON error lines, prompts, stateful sites/users/databases/templates/certificates | one executable under `test/sim/`, grammar derived from COMMAND-REFERENCE and recorded outputs |
| Integration | the real server over stdio with the SDK client: every tool × every approval outcome × both protocol eras × client with/without elicitation; fake `ssh` for argv | in-repo |
| Mutation | ~230 mutants of the guards (class gate, patterns, quoting, approval checks and limits, protected targets, file kinds and ports, redaction, plan token, rate limit, the gate, the secrets directory, the release workflow checks); each must fail a test | `npm run mutation` (`-- --check` verifies in seconds that every mutant still applies) |
| Gate | the bash gate vs. the TypeScript validators on one corpus | in-repo, needs bash |
| Docs | tool reference generated from the code; COMMAND-REFERENCE index equals the catalogue; no personal data in the tree | in-repo |
| Contract (opt-in) | the catalogue against a real CloudPanel with throwaway names, baseline before and after, deletes what it creates | `npm run contract-test`, maintainers only, refuses to run without explicit flags |
| Review | independent adversarial security review, no open high or medium finding at release | before publishing |

## 11. Release and repository hygiene

README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, CHANGELOG, issue and PR templates; CI (Node 22 and 24 on Linux, macOS, Windows), CodeQL,
dependency review, Dependabot; a release workflow with npm provenance that is prepared and inactive; exact-pinned dependencies and lockfile;
`.npmrc` with `ignore-scripts`; no install scripts; no committed build output; `files` in `package.json` limits what is published. Before every
commit that matters the tree and history are scanned for personal data (the maintainers' names, hosts, addresses). Nothing is published without the
maintainers' explicit word.

## 12. Decisions (2026-11-05)

1. **Name:** `cloudpanel-mcp-server` for the repository and the npm package. The README states that the project is unofficial and not affiliated with
   CloudPanel, and that the name says what the software works with.
2. **Licence:** Apache-2.0.
3. **Hosting:** the repository is created on GitHub **private first**; commits carry GitHub's `ID+user@users.noreply.github.com` identity from the first
   publication on (the local identity stays a placeholder until then).
4. **Optional inventory companion:** included, opt-in, unofficial ([ADR-0003](adr/0003-optional-inventory.md)).
5. **Publication is a deliberate step:** nothing is made public (repository, npm package) without an explicit decision by the maintainers, and making a
   repository public is a separate step from creating it.
