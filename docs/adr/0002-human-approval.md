# ADR-0002: Human approval of destructive and admin actions

- Status: accepted (2026-11-05)

## Context

A requirement from the start: destructive and admin actions need permission, "never a string the model can type itself". Research
(RESEARCH-MCP-APPROVALS) shows: MCP annotations are hints; Claude Code prompts from permission rules, not from `destructiveHint`; only `ask` rules and
tools marked `_meta["anthropic/requiresUserInteraction"]: true` always reach a human there; elicitation is the protocol's way for a server to ask the user
(Claude Code ≥ 2.1.76, VS Code Copilot yes; Claude Desktop undocumented; Cursor and Zed unreliable or absent).
A model-supplied `confirm: "<name>"` parameter (the prototype's design and the other CloudPanel gateway's `confirm: true`) is a string the model types.

## Decision

1. **Elicitation is the approval.** The server builds the question from validated state and asks through the client. `accept` with valid content
   is the only success. Decline, cancel, timeout, error, mismatch and "client cannot ask" all refuse, and each is audited.
2. **Typed target for DESTRUCTIVE and ADMIN**, a ticked box for WRITE (operator may switch WRITE to "the client asks" with `approval.write: "client"`).
   DESTRUCTIVE and ADMIN have no off switch and no unattended mode.
3. **No elicitation → refuse and print the exact command** for the human's own terminal.
4. **A plan token** from a dry run is required for DESTRUCTIVE and ADMIN calls (HMAC over tool, profile and canonical arguments; expiry; single use).
5. **Claude Code's own gate** via `_meta["anthropic/requiresUserInteraction"]: true` on DESTRUCTIVE and ADMIN tools, plus README rules for
   `permissions.ask` and VS Code.
6. **Operator gates** remove classes entirely; **protected targets** and **rate limits** apply on top; **the audit log** records every decision.
7. The documentation states the limits: accept proves only that the client said so; hooks and bypass modes can auto-accept; same-user processes are not
   stopped.

## Rejected

- A `confirm` parameter, a one-time code returned to the model, or any token the model can read and replay as "approval".
- An out-of-band terminal prompt on `/dev/tty` or a local HTTP port: reachable by a model that has a shell, and absent on Windows and in containers.
- A FIDO2-key SSH approver: strongest, but needs hardware; offered in the README as an optional hardening for the SSH key, not built in.
- An "unattended" setting for destructive actions: users with headless agents run the printed command instead.

## Consequences

Clients without elicitation can read and (with `approval.write: "client"`) create, but cannot delete or administer through the model. This is
intentional. Honest limits are in SPEC §4.8 and the README.
