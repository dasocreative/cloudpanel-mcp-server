/**
 * What the official documentation and the observed servers say about clpctl commands, for
 * clp_list_commands. docs/COMMAND-REFERENCE.md is the full reference; test/docs.test.ts keeps the
 * two in step.
 */
export interface KnownCommand {
  readonly command: string;
  readonly source: "docs" | "docs-update-page" | "docs-cron-line" | "observed";
  /** Why there is no tool, or null when there is one. */
  readonly notWrapped: string | null;
}

export const KNOWN_COMMANDS: readonly KnownCommand[] = [
  { command: "cloudflare:update:ips", source: "docs", notWrapped: null },
  { command: "cloudpanel:enable:basic-auth", source: "docs", notWrapped: null },
  { command: "cloudpanel:disable:basic-auth", source: "docs", notWrapped: null },
  { command: "cloudpanel:set:release-channel", source: "docs-update-page", notWrapped: null },
  { command: "db:show:master-credentials", source: "docs", notWrapped: null },
  { command: "db:add", source: "docs", notWrapped: null },
  { command: "db:delete", source: "observed", notWrapped: null },
  { command: "db:export", source: "docs", notWrapped: null },
  { command: "db:import", source: "docs", notWrapped: null },
  { command: "db:backup", source: "docs-cron-line", notWrapped: "it is CloudPanel's nightly cron job, not a user command" },
  { command: "lets-encrypt:install:certificate", source: "docs", notWrapped: null },
  { command: "site:add:nodejs", source: "docs", notWrapped: null },
  { command: "site:add:static", source: "docs", notWrapped: null },
  { command: "site:add:php", source: "docs", notWrapped: null },
  { command: "site:add:python", source: "docs", notWrapped: null },
  { command: "site:add:reverse-proxy", source: "docs", notWrapped: null },
  { command: "site:install:certificate", source: "docs", notWrapped: null },
  { command: "site:delete", source: "docs", notWrapped: null },
  { command: "system:permissions:reset", source: "docs", notWrapped: null },
  { command: "user:add", source: "docs", notWrapped: null },
  { command: "user:delete", source: "docs", notWrapped: null },
  { command: "user:list", source: "docs", notWrapped: null },
  { command: "user:reset:password", source: "docs", notWrapped: null },
  { command: "user:disable:mfa", source: "docs", notWrapped: null },
  { command: "varnish-cache:purge", source: "docs", notWrapped: null },
  { command: "vhost-templates:import", source: "docs", notWrapped: null },
  { command: "vhost-templates:list", source: "docs", notWrapped: null },
  { command: "vhost-template:add", source: "docs", notWrapped: null },
  { command: "vhost-template:delete", source: "docs", notWrapped: null },
  { command: "vhost-template:view", source: "docs", notWrapped: null },
];
