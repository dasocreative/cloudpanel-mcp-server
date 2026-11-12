import * as z from "zod/v4";
import { READ_ONLY, UNTRUSTED, defineTool, type ToolSpec } from "../define.ts";

export const metaTools: ToolSpec[] = [
  defineTool({
    name: "clp_server_info",
    kind: "meta",
    command: null,
    cls: "read",
    title: "Profiles, safety settings and what this CloudPanel supports",
    summary:
      "Call this first. Returns, for each configured server profile: which classes of tools are enabled, the protected targets, allowed file directories, rate limits, how a human approves (whether THIS client can show an approval form) and, for the selected profile, the commands the server's clpctl lists with any tool that is unavailable on it. Changes nothing.",
    shape: {
      refresh: z.boolean().optional().describe("true: probe the server's clpctl again instead of using the cached answer."),
    },
    annotations: READ_ONLY,
  }),
  defineTool({
    name: "clp_list_commands",
    kind: "meta",
    command: null,
    cls: "read",
    title: "List the clpctl commands of the server",
    summary:
      "Runs clpctl with no arguments (CloudPanel's own usage listing) and compares it with the documented command set: which documented commands the server lacks, which commands it has that this server has no tool for (reported only, never callable: there is no raw command tool), and which options each command shows.",
    shape: {
      refresh: z.boolean().optional().describe("true: probe again instead of using the cached answer."),
    },
    annotations: READ_ONLY,
  }),
  defineTool({
    name: "clp_inventory_sites",
    kind: "inventory",
    command: null,
    cls: "read",
    title: "List the sites on the server (unofficial companion)",
    summary:
      "Lists the sites by reading the NGINX vhost files through a small read-only script that the server's owner installed (NOT part of CloudPanel; clpctl cannot list sites). The site type is a guess from the vhost. Only available when the profile enables the inventory. " + UNTRUSTED,
    shape: {},
    annotations: READ_ONLY,
  }),
];
