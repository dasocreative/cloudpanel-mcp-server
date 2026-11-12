/**
 * `--print-server-setup`: the server setup script of this release with the gate and the inventory helper of
 * the same release embedded, so that one command sent over ssh prepares a server, and what runs there is
 * exactly what this package contains (no download on the server).
 */

export const EMBED_START = "# @@EMBEDDED-START";
export const EMBED_END = "# @@EMBEDDED-END";
const GATE_EOF = "CLOUDPANEL_MCP_GATE_EOF";
const INVENTORY_EOF = "CLOUDPANEL_MCP_INVENTORY_EOF";

function heredocFunction(name: string, terminator: string, text: string): string {
  const body = text.endsWith("\n") ? text : `${text}\n`;
  if (body.split("\n").includes(terminator)) throw new Error(`${name}: the embedded file contains its own terminator line`);
  return `${name}() {\n  cat <<'${terminator}'\n${body}${terminator}\n}\n`;
}

export function bundleServerSetup(setup: string, gate: string, inventory: string, version: string): string {
  const start = setup.indexOf(`\n${EMBED_START}\n`);
  const end = setup.indexOf(`\n${EMBED_END}\n`);
  if (start < 0 || end < start) throw new Error("the setup script has no embedded block");
  const head = setup.slice(0, start + 1 + EMBED_START.length + 1);
  const tail = setup.slice(end + 1);
  const pinned = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(version) ? version : "<version>";
  return (head + heredocFunction("embedded_gate", GATE_EOF, gate) + heredocFunction("embedded_inventory", INVENTORY_EOF, inventory) + tail).replaceAll(
    "cloudpanel-mcp-server@<version>",
    `cloudpanel-mcp-server@${pinned}`,
  );
}
