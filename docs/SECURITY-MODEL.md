# Security model

What stops an AI assistant, a confused model or a stolen key from doing damage, and what nothing here can stop.
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Approving changes

When a call changes something, the server asks **you**, through your client's *approval form* (MCP elicitation), with a question it builds itself: the server, the
exact command and its effects. To delete or administer something you **type the target's name** (the domain, database, user or template); for adding and updating
you tick a box. Decline, cancel, a wrong name, a timeout or an error all mean *no*, and no parameter the model fills in can approve for you. Destructive and admin
calls also need a dry run of exactly the same arguments first (a signed, single-use plan token).

**A client that cannot show the form** still reads everything, but runs nothing that changes: the tool answers with the exact `clpctl` command so you can run it
yourself in a terminal. If you know your client asks you before every tool call anyway, you may let it approve **adds and updates only** with `"approval": { "write":
"client" }` in the profile; deleting and administering have no such switch and no unattended mode.

Keep your client's own tool confirmation on for this server, and do not "always allow" its changing tools. In Claude Code, destructive and admin tools are marked
"ask on every call" (`_meta["anthropic/requiresUserInteraction"]`): it prompts even in auto and bypass modes. You can add your own rule in `~/.claude/settings.json`:

```json
{ "permissions": { "ask": ["mcp__cloudpanel__*"] } }
```

## Layers of protection

An assistant that can run `clpctl` as root can create and delete sites and databases, issue certificates, add administrators to the panel and switch
off two-factor authentication. The model can be wrong, or can be steered by text it reads on a web page, in a file or in a command's output. So:

| Layer | What it does |
| ----- | ------------ |
| **Read-only by default** | With no `allow` setting only the read tools are even listed. Changing tools exist only for the classes you enable, per server. |
| **Four classes** | READ, WRITE (adds or updates), DESTRUCTIVE (removes or overwrites), ADMIN (who can get into the panel). Independent switches. |
| **One tool, one documented command** | No raw command, no shell, no free text. Unknown commands your server prints are listed, never callable. |
| **Strict values** | Every value is checked against a narrow allow-list pattern before it is quoted; options are single `--name=value` tokens, so a value can never become an option; each file must be in the subdirectory of a directory you name that belongs to its kind (`dumps/`, `certs/`, `templates/`) and have that kind's extension; application ports must be ports you list (by default only the usual web-app ports) and are never databases, caches or admin APIs; reverse-proxy targets must be hosts you allow. Locally there is no shell at all. |
| **Dry run and plan token** | Every changing tool can show the exact command and its effects without running it. Destructive and admin tools *require* the token of a dry run of exactly the same arguments (signed, 10 minutes, single use). |
| **Human approval** | See [Approving changes](#approving-changes). |
| **Protected targets** | Domains, site users, databases and panel users you list can never be the target of a changing tool (deleted, overwritten, reset, given a certificate or a database, created again); system names (`root`, `mysql`, the panel's own database, ...) are always protected. A protected *site user* or *database* guards the tools that name it: deleting a site removes its user and databases with it, so protect the **domain** of every site that must survive. `clp_server_info` and `--check-config` warn about this. |
| **Rate limits** | Per server and class, never unlimited for destructive and admin calls. |
| **No secret through the model** | No tool takes a password. The server generates 32 random characters, writes them to a `0600` file on your machine *before* the command runs and returns only the path. Output is scrubbed of them. |
| **Audit log** | Every changing call, every approval question and decision (asked, accept, decline, cancel, timeout, unsupported), every read and every refusal is appended to `audit.jsonl` (mode `0600`); the records that precede a changing command are written *before* it runs, and if they cannot be written the command does not run. Refusals, dry runs and reads are written at most 120 a minute per kind of record (about twenty kinds; the rest are counted, and the count is written), so a looping model can make the log grow only slowly. If the disk does fill, changing tools refuse to run. |
| **Output is untrusted data** | stdout/stderr are stripped of escape sequences, bounded, labelled, and never treated as instructions. |
| **Server-side gate** | A forced-command script generated from the same catalogue limits the SSH key itself to the same commands, values and class ceilings. The setup script installs it. See [The gate](#the-gate). |
| **Small supply chain** | Three runtime packages (`@modelcontextprotocol/server`, its `core`, `zod`), exact versions, a lockfile, no install scripts, no committed build output, npm provenance on release. |

## Honest limits

Read these. No tool-calling setup can promise more.

- **"Accept" proves only that the client said so.** Hooks, bypass modes and SDK callbacks can auto-accept (Claude Code's `Elicitation` hooks, GitHub Copilot
  CLI's autopilot); a client's UI can fail to render the question. The forms always have a required field (a typed name, or a box that starts unticked), so a
  client that accepts an empty form is refused.
  Annotations and the Claude Code metadata are *hints* that a client may ignore.
- **Anything running as your OS user can do what this server can**: read the audit log and password files, edit the configuration, call `ssh` directly.
  A model that also has a shell tool on your machine is not stopped by file permissions or approvals here. In Claude Code you can at least keep its *file tools*
  away from the state directory and the configuration (`~/.claude/settings.json`; use the path your platform shows in `--check-config`):

  ```json
  { "permissions": { "deny": [
      "Read(~/.local/state/cloudpanel-mcp-server/**)",
      "Read(~/.config/cloudpanel-mcp-server/**)"
  ] } }
  ```

  (macOS: `~/Library/Application Support/cloudpanel-mcp-server/**`.) This does not stop a shell command such as `cat` unless you also use Claude Code's sandbox:
  it narrows the exposure, it does not remove it. Better still, run the assistant as a different OS user than the one that owns the state directory.
- **Passwords are command-line arguments** because that is how `clpctl` takes them: `sudo` logs them and `ps` shows them while the command runs, on the server
  and on the machine that runs `ssh`. Treat a generated password as a first-login password and change it.
- **A dump you import runs.** `clp_db_import` feeds a dump to the database as SQL. A dump that came from a database an attacker influences (a hacked site) is
  attacker-controlled SQL when it is imported elsewhere, and a `mysql` client can run shell commands from some of its meta-commands. Import only dumps you trust;
  the human who types the database name to approve is the safeguard.
- **The server cannot know which domain is "production".** Protected targets protect what you list. List your panel's domain and your live sites; a site's
  user and databases go with the site, so listing them without the domain does not protect them from `clp_site_delete`.
- **`clpctl` is the authority.** Patterns here are conservative, not complete; CloudPanel's own refusals are returned as they are.
- Windows has no POSIX file modes: the audit log and password files inherit your profile's permissions.
- Installing this server and its SSH access is a security decision of its own: a stolen key is as powerful as its sudoers rule, unless you add the gate. Even
  with the gate, the write class can create a site user with a password the key's holder chooses, which is a way to get an unprivileged shell if the server
  accepts SSH passwords; see [The gate](#the-gate).

See [SECURITY.md](../SECURITY.md) to report a vulnerability.

## The gate

The setup script installs it. Without it, whoever holds the SSH key is as powerful as its sudoers line: every `clpctl` command. The **gate**
(`/usr/local/sbin/cloudpanel-mcp-gate.sh`) is a forced command: the key can only run what this project can send, with the same commands, the same value types and a
ceiling on classes. It is generated from the tool catalogue ([hardening/cloudpanel-mcp-gate.sh](../hardening/cloudpanel-mcp-gate.sh)), so it cannot drift.

Its settings block, at the top of the installed file, is yours to edit as root:

- `ALLOW_WRITE`, `ALLOW_DESTRUCTIVE`, `ALLOW_ADMIN`: the ceiling (`--allow` of the setup script sets them). Keep them at or above the profile's `allow`, or the gate
  refuses what the profile permits.
- `PROTECT_DOMAINS` (and `PROTECT_SITE_USERS`, `PROTECT_DATABASES`, `PROTECT_PANEL_USERS`): **list your live sites here**, e.g.
  `PROTECT_DOMAINS=(shop.example.com '*.example.org')`. The key can then never delete, overwrite or reset them, whatever the client says.
- `ALLOWED_FILE_DIRS`, `APP_PORTS`, `PROXY_HOSTS`: keep them equal to the profile's `fileDirs`, `appPorts`, `proxyHosts`.

Test it: `ssh -i ~/.ssh/id_ed25519_cloudpanel cloudpanel-mcp@203.0.113.10 ls` must answer `cloudpanel-mcp-gate: refused: ...`.

**What the gate cannot do.** It checks the *shape* of what the key may run, not the intent. With `ALLOW_WRITE=1` the holder of a stolen key can still add a site with
a site user and a password of their own choosing, and a site user may be able to log in over SSH with it: an unprivileged shell, not root, but a foothold. So keep
SSH password logins off on the server (`PasswordAuthentication no`), protect your production domains in the gate, and consider a second, read-only key and profile
(`--allow read`) for everyday use. The typed confirmation happens in your client and cannot be enforced server-side.
