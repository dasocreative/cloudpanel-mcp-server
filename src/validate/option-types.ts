import {
  MAX_DOMAIN_LIST,
  RE,
  RESERVED_DATABASES,
  RESERVED_DB_USERS,
  RESERVED_SITE_USERS,
  USER_ROLES,
  USER_STATUS,
  RELEASE_CHANNELS,
  isAllowedProxyUrl,
  isAppPort,
  isDomain,
  isKindPath,
  parsePurge,
  type PatternName,
  type PortRange,
} from "./patterns.ts";

/**
 * How the value of a clpctl option is validated. The single definition of "a valid option value":
 * the engine checks every option of a plan against it right before running (so a bug in a tool
 * cannot put an unchecked value on a command line), the hardened-mode gate re-implements it in
 * bash, and the tests use it as the oracle for that script.
 */
export type OptionType =
  | PatternName
  | "userDbName"
  | "port"
  | "domainList"
  | "dumpPath"
  | "certPath"
  | "templatePath"
  | "role"
  | "status"
  | "channel"
  | "purge"
  | "password";

export interface OptionContext {
  readonly fileDirs: readonly string[];
  readonly proxyHosts: readonly string[];
  readonly appPorts: readonly PortRange[];
}

const PORT_TEXT = /^[1-9][0-9]{0,4}$/;

export function isValidOption(type: OptionType, value: string, ctx: OptionContext): boolean {
  switch (type) {
    case "domain":
      return isDomain(value);
    case "siteUser":
      return RE.siteUser.test(value) && !RESERVED_SITE_USERS.includes(value);
    case "dbUser":
      return RE.dbUser.test(value) && !RESERVED_DB_USERS.includes(value.toLowerCase());
    case "userDbName":
      return RE.dbName.test(value) && !RESERVED_DATABASES.includes(value.toLowerCase());
    case "email":
      return value.length <= 254 && RE.email.test(value);
    case "port":
      return PORT_TEXT.test(value) && isAppPort(Number(value), ctx.appPorts);
    case "domainList": {
      const parts = value.split(",");
      return parts.length >= 1 && parts.length <= MAX_DOMAIN_LIST && parts.every(isDomain);
    }
    case "dumpPath":
      return isKindPath("dump", value, ctx.fileDirs);
    case "certPath":
      return isKindPath("cert", value, ctx.fileDirs);
    case "templatePath":
      return isKindPath("template", value, ctx.fileDirs);
    case "proxyUrl":
      return isAllowedProxyUrl(value, ctx.proxyHosts, ctx.appPorts);
    case "role":
      return (USER_ROLES as readonly string[]).includes(value);
    case "status":
      return (USER_STATUS as readonly string[]).includes(value);
    case "channel":
      return (RELEASE_CHANNELS as readonly string[]).includes(value);
    case "purge":
      return parsePurge(value) !== null;
    case "password":
      return RE.generatedPassword.test(value);
    default:
      return RE[type].test(value);
  }
}
