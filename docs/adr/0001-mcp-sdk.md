# ADR-0001: MCP SDK — `@modelcontextprotocol/server` 2.x

- Status: accepted (2026-11-05), by a spike
- Deciders: maintainers

## Context

The brief asks to choose between `@modelcontextprotocol/sdk` 1.x (latest 1.32.2, MCP spec up to 2025-11-25, maintenance-only) and the v2 package
`@modelcontextprotocol/server` (2.4.0, spec 2026-07-28 and the older eras), and to decide by a short spike.

## Spike (2026-11-05, Node 24, throw-away code outside the repository)

One tool with `destructiveHint`, `_meta["anthropic/requiresUserInteraction"]` and a typed-name confirmation, built on both SDKs, then run against
clients of both generations.

| Server | Client | Result |
| ------ | ------ | ------ |
| v2 `serveStdio` + `inputRequired` | SDK 1.32.2 client (2025 era), form capability | elicitation round trip works; right name runs, wrong name / decline / cancel refuse |
| v2 | SDK 1.32.2 client, bare `{elicitation: {}}` (form only) | works |
| v2 | SDK 1.32.2 client, no elicitation capability | refused with a clear tool error |
| v2 | v2 client, default (legacy) mode | works |
| v2 | v2 client, `auto` and pinned `2026-07-28` | works; the same handler is re-entered with the answers |
| v2 | v2 client, modern era, no capability | JSON-RPC error `-32021` unless the handler checks the capability first (it must) |
| 1.x low-level server + `elicitInput` | SDK 1.x client | works |
| 1.x server | v2 client legacy / auto | works; pinned `2026-07-28` fails (1.x is 2025-only) |

`_meta` and annotations reach `tools/list` unchanged on both. Claude Code declares `elicitation: {form: {}, url: {}}` for stdio servers on both
protocol eras since v2.1.287 (its MCP documentation, read 2026-11-05).

Footprint of a stdio server: **1.x installs 95 packages (26 MB)** (express, hono, jose, ajv, cors, eventsource, ...) of which none is needed for stdio;
**v2 server-only installs 3** (`@modelcontextprotocol/server`, `@modelcontextprotocol/core`, `zod`; 16 MB), Apache-2.0 and MIT, no install scripts.

## Decision

Use **`@modelcontextprotocol/server` 2.4.0** with `serveStdio`, exact-pinned, plus `zod` 4.6.7. Write each approval as an "input required" step once; the
SDK serves 2025-era clients through its legacy shim (a pushed `elicitation/create`, then the handler is re-entered with the answers) and 2026-era
clients through the retried call.

## Refinement: the low-level `Server`

The tool list and call handlers are registered on the SDK's low-level `Server` (`tools/list`, `tools/call`) and not through `McpServer.registerTool`, so that
this project validates arguments itself: an invalid call is then audited and refused with a message that never echoes the value, instead of being rejected
by the SDK before any of our code runs. The JSON Schemas shown to the model are generated from the same zod schemas that validate (`z.toJSONSchema`).
In the older protocol era the approval uses `ctx.mcpReq.elicitInput` with a ten-minute timeout (so a timeout can be told from a decline and audited); in the
2026-07-28 era the handler returns `inputRequired(...)` and is run again with the answer. A second spike run (2026-11-05) confirmed both paths against the
SDK 1.x client and the v2 client in `legacy`, `auto` and pinned `2026-07-28` modes.

## Consequences

- Smallest possible runtime dependency tree for a server that holds SSH access to production hosts.
- The handler runs again after the human answered, so everything before the approval must be free of side effects, and answers are bound to the call
  by a key derived from tool, profile and arguments.
- The capability check (`elicitation.form`) is done by the server before asking, in both eras (`envelope["io.modelcontextprotocol/clientCapabilities"]`
  for the modern era, `getClientCapabilities()` for the legacy one), so an unsupported client gets the "run this yourself" refusal and not a protocol
  error.
- v2 is three months old: minor releases may move APIs. Mitigation: exact pins, an integration suite that exercises both eras, Dependabot PRs reviewed
  by hand. Fallback: the same catalogue can be served by 1.x, because the SDK is confined to `src/mcp/`.
- A no-SDK server (hand-written JSON-RPC) was rejected: zero dependencies, but protocol negotiation and two protocol eras would be ours to maintain.
