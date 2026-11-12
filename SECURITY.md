# Security policy

This project gives an AI assistant a way to run CloudPanel's `clpctl` on servers, so its safety properties are its main feature. Reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use the repository's **Security** tab, **Report a vulnerability** (GitHub private vulnerability reporting), and include:

- what you found and which version (`cloudpanel-mcp-server --version`) and commit it affects;
- the smallest set of steps or a failing test that shows it;
- what an attacker could do with it and what they would need first (a prompt-injected model, a hostile `clpctl` output, a stolen SSH key, local access, ...).

Do not include real server addresses, keys or passwords. You can expect an acknowledgement within a few days; this is a volunteer project, so fixes are
best-effort, but anything that lets a model delete, overwrite or reconfigure without a human's approval, or that leaks a secret, is treated as the highest priority.

## Supported versions

Only the latest release receives fixes. Pin the version you install and read the [CHANGELOG](CHANGELOG.md).

## What counts as a vulnerability

In scope (examples):

- a way to make the server run something other than a documented `clpctl` command, or run one with an argument that did not pass its validation (injection, option smuggling, path traversal, a port or upstream that should have been refused);
- a way for a model to approve its own destructive or admin action, to bypass a class gate, a protected target, the plan token or a rate limit;
- a secret (a generated password, the master credentials) appearing in a tool result, an error, the audit log or stderr, or stored with permissions looser than documented;
- the hardened-mode gate accepting a command line the server would not send, or the inventory script printing or reading more than documented;
- a dependency or release problem (an install script, a committed build artifact, an unpinned dependency).

Out of scope: vulnerabilities in CloudPanel itself (report them to its vendor; its changelog lists security fixes, so keep it updated), in your MCP client, or in the
operating system; the limits documented under *Honest limits* in docs/SECURITY-MODEL.md (for example a model that also has a shell tool on the same machine, or a client that
auto-accepts approval questions, is not defended against by this project).

## Design notes for reviewers

[docs/SPEC.md](docs/SPEC.md) has the threat model; [docs/adr](docs/adr) the reasons for the approval design; `npm run mutation` shows which guards the tests prove.
