# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once released.

## [Unreleased]

## [0.1.0] - 2026-11-12

First public release.

### Added

- An MCP server (stdio) with typed tools for every documented `clpctl` v2 command: PHP, Node.js, Python, static and reverse-proxy sites, Let's Encrypt and
  custom certificates, databases, vhost templates, panel users, the panel's Basic Auth and release channel, the Cloudflare IP list, and the two site-user commands.
- Read-only by default; WRITE, DESTRUCTIVE and ADMIN classes switched on per server profile.
- Human approval through MCP elicitation (typed target name for destructive and admin actions), dry runs with signed single-use plan tokens, protected targets,
  rate limits, an audit log, generated passwords stored in private files and never returned.
- Feature detection from the server's own `clpctl` listing; version values checked by shape.
- Several server profiles, SSH (any port and key) or local execution, macOS, Linux and Windows clients.
- Hardened mode: a forced-command gate generated from the tool catalogue.
- An optional, unofficial, read-only inventory script.
- Easy setup: `--print-server-setup` prints a script (with the gate and the inventory helper of the same release embedded) that prepares a server in one
  command sent over ssh: a dedicated account, one sudoers line, the file directories, the gate at the level you choose, the key pinned to it, a check of the
  sshd settings that would refuse the account, and a test of the whole chain. `--init` writes the client configuration for one server (never over an
  existing file) so that MCP clients need no setting at all, and `--check-connection` logs in and says in plain words what is wrong when it fails.
- A short README with the setup in five steps and copy-paste registration for Claude Code, Codex, Gemini CLI, OpenCode, Pi, Copilot CLI and others;
  the details in docs/ (SETUP, CLIENTS, CONFIGURATION, SECURITY-MODEL, TOOLS, TROUBLESHOOTING).
- Tests: validators with properties and fuzzing, quoting through real shells, a strict `clpctl` simulator, the server over stdio with clients of both MCP
  protocol eras, the gate against the validators on bash 3.2 and 5.x, a mutation check of ~100 guards.

### Security

- An independent security review before the first release; its findings and fixes are in [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md). Highlights: output
  that holds secrets is never shown, also when saving it fails; one uniform protect rule for every changing tool; a subdirectory and extensions per kind of
  file (`dumps/`, `certs/`, `templates/`); a per-profile allowlist of application ports; approval questions limited and asked one at a time; server text bounded
  and labelled in one `output` object; a release workflow in which no job that runs repository code can publish. A second review round added: ssh connection
  sockets per login, file directories refused where other accounts can write, a remembered open question per profile in the 2026 protocol era, redaction that
  cleans before it searches, every default-ignorable code point removed, and reads, refusals and dry runs bounded in the audit log. A third round made the 2026-era question claim atomic, extended the denied ports and the places a file directory
  may not be in (mirrored and validated in the gate), and documented how to set up a safe release (docs/RELEASING.md). A fourth round, after the live tests:
  a changing command that leaves a yes/no question of `clpctl` unanswered is reported as not confirmed instead of done, for every tool; the plan token is used up
  in the same step that takes the human's answer; an error line is found even where scrubbing would have cut into it; the audit log records every read and
  always says how many records it held back.

### Fixed

- A plan token is accepted only in the exact spelling it was issued in (base64url ignores the unused bits of the last character).
- Unix socket paths for ssh connection sharing are built with `/` on every platform; tests that assumed a Unix host now pass on Windows.

[Unreleased]: https://github.com/dasocreative/cloudpanel-mcp-server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dasocreative/cloudpanel-mcp-server/releases/tag/v0.1.0
