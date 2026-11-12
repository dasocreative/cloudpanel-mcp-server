# Connect your AI agent

After the [setup](SETUP.md) (`--init` saved the connection), every client starts the same command with **no settings of its own**:
`npx -y cloudpanel-mcp-server@0.1.0`. Register it once, as `cloudpanel`.

## Claude Code

```bash
claude mcp add --transport stdio --scope user cloudpanel -- npx -y cloudpanel-mcp-server@0.1.0
```

## Codex

```bash
codex mcp add cloudpanel -- npx -y cloudpanel-mcp-server@0.1.0
```

Then give the first start more than Codex's default 10 seconds, in `~/.codex/config.toml`:

```toml
[mcp_servers.cloudpanel]
command = "npx"
args = ["-y", "cloudpanel-mcp-server@0.1.0"]
startup_timeout_sec = 60
```

If you use a granular `approval_policy`, set `mcp_elicitations = true` in it, or Codex declines every approval form.

## Gemini CLI

```bash
gemini mcp add -s user cloudpanel npx -- -y cloudpanel-mcp-server@0.1.0
```

or in `~/.gemini/settings.json` (keep `trust` off, so Gemini asks you before each tool call):

```json
{ "mcpServers": { "cloudpanel": { "command": "npx", "args": ["-y", "cloudpanel-mcp-server@0.1.0"], "trust": false } } }
```

## OpenCode

```bash
opencode mcp add cloudpanel --global -- npx -y cloudpanel-mcp-server@0.1.0
```

or in `~/.config/opencode/opencode.json` (OpenCode 2.x; 1.x has the server directly under `"mcp"`, with `"enabled": true`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": { "servers": { "cloudpanel": { "type": "local", "command": ["npx", "-y", "cloudpanel-mcp-server@0.1.0"] } } }
}
```

## Pi

Pi 0.99 or newer has MCP built in:

```bash
pi mcp add cloudpanel -- npx -y cloudpanel-mcp-server@0.1.0
```

or in `~/.pi/agent/mcp.json`: `{ "mcpServers": { "cloudpanel": { "command": "npx", "args": ["-y", "cloudpanel-mcp-server@0.1.0"] } } }`. Run `/reload` in an
open session.

## VS Code (GitHub Copilot)

```bash
code --add-mcp '{"name":"cloudpanel","type":"stdio","command":"npx","args":["-y","cloudpanel-mcp-server@0.1.0"]}'
```

## GitHub Copilot CLI

```bash
copilot mcp add cloudpanel -- npx -y cloudpanel-mcp-server@0.1.0
```

## Goose

In `~/.config/goose/config.yaml` (or `goose configure`, *Add Extension*, *Command-line Extension*):

```yaml
extensions:
  cloudpanel:
    type: stdio
    name: cloudpanel
    enabled: true
    cmd: npx
    args: [-y, cloudpanel-mcp-server@0.1.0]
    timeout: 300
```

## Cursor, Kiro, Claude Desktop, Windsurf, Cline, Qwen Code and other `mcpServers` clients

The same block everywhere; only the file differs:

```json
{ "mcpServers": { "cloudpanel": { "command": "npx", "args": ["-y", "cloudpanel-mcp-server@0.1.0"] } } }
```

| Client | File |
| ------ | ---- |
| Cursor | `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project) |
| Kiro | `~/.kiro/settings/mcp.json`; the CLI's 5-second start limit is too short for a first `npx` run: `kiro-cli settings mcp.initTimeout 60000` |
| Claude Desktop | `claude_desktop_config.json` (Settings, Developer, Edit Config); quit the app fully after editing |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline | `cline_mcp_settings.json` (MCP Servers, Configure); add `"timeout": 120` next to `"args"` |
| Qwen Code | `~/.qwen/settings.json` (or `qwen mcp add cloudpanel npx -y cloudpanel-mcp-server@0.1.0`) |

## Zed

In Zed's `settings.json`:

```json
{ "context_servers": { "cloudpanel": { "command": "npx", "args": ["-y", "cloudpanel-mcp-server@0.1.0"] } } }
```

## Any other MCP client

A local **stdio** server: command `npx`, arguments `-y cloudpanel-mcp-server@0.1.0`, no environment variables.

- **Desktop apps** (Claude Desktop, Cursor, ...) do not see your shell's `PATH`: if the server does not start, put the absolute path of `npx` (`command -v npx`,
  e.g. `/opt/homebrew/bin/npx`) in `command`.
- **The first start downloads the package**, which can exceed a client's start limit (10 seconds in Codex, Cline and Crush). Raise it as shown above, or install the
  package once (`npm install -g cloudpanel-mcp-server@0.1.0`) and use `cloudpanel-mcp-server` as the command, with no arguments.
- **A key with a passphrase** needs `ssh-agent`, and several clients do not pass `SSH_AUTH_SOCK` to the server (Codex: add `env_vars = ["SSH_AUTH_SOCK"]`;
  Gemini CLI and Claude Desktop drop it). The dedicated key of step 1, without passphrase and pinned to the gate, avoids this.

## Which clients can approve changes

Reading works in every client. To **change** something the client must show the server's approval form (MCP *elicitation*). As of November 2026:

| Client | Approval forms | Notes |
| ------ | -------------- | ----- |
| Claude Code | yes | |
| Codex | yes (0.119+) | `mcp_elicitations = true` with a granular `approval_policy`; `codex exec` declines every form |
| OpenCode | yes (2.2+) | 1.x: no; `opencode run` cancels every form |
| Cursor | yes (1.5+) | |
| VS Code (GitHub Copilot) | yes (1.102+) | forms are cancelled in Autopilot |
| GitHub Copilot CLI | yes | **autopilot answers forms by itself**: do not enable write classes for a session in autopilot |
| Goose | yes (1.21.2+) | |
| Kiro | yes | |
| Gemini CLI, Pi, Claude Desktop, Windsurf, Cline, Zed, Qwen Code, Crush, Amp (local servers) | no | see below |

In a client **without** forms, the assistant can look at everything, and for each change it gives you the exact `clpctl` command to run yourself. If the client
asks you before every tool call (Gemini CLI with `trust` off does), you may let it approve **adds and updates only** with `"approval": { "write": "client" }` in the
profile; deleting and administering always need a form.
