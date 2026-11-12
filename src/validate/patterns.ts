/**
 * Strict value types. Every pattern is written so that it means exactly the same thing as a
 * JavaScript RegExp and as a POSIX extended regular expression: only anchors, bracket expressions
 * without backslashes, groups, alternation and {m,n} (a "\." outside a bracket is allowed).
 * scripts/gen-gate.ts copies these sources into the hardened-mode bash gate; test/gate.test.ts runs
 * both implementations on one corpus.
 *
 * No value ever starts with "-" (a type would have to allow it explicitly), and none can hold a
 * quote, a space (except template names), a newline, a NUL, a backslash, "$", a backtick, ";",
 * "&", "|", "<", ">", "(", ")", "*", "?", "{", "}", "~", "#" or "!".
 */
export const SOURCES = {
  // lowercase DNS hostname, at least two labels, TLD of two or more characters (punycode allowed)
  domain: String.raw`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`,
  siteUser: "^[a-z][a-z0-9_-]{0,31}$",
  // Observed on CloudPanel 2.5.4: an underscore in a database name is rejected,
  // a hyphen is accepted. Letters, digits and "-" only.
  dbName: "^[A-Za-z0-9][A-Za-z0-9-]{0,63}$",
  dbUser: "^[A-Za-z0-9_]{1,64}$",
  // "Generic", "My Application", "PrestaShop 1.7": starts with a letter or digit, no trailing space
  templateName: "^[A-Za-z0-9]([A-Za-z0-9 ._-]{0,62}[A-Za-z0-9._-])?$",
  panelUser: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
  email: String.raw`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`,
  person: "^[A-Za-z]([A-Za-z -]{0,62}[A-Za-z])?$",
  timezone: "^[A-Za-z][A-Za-z0-9_+-]{0,31}(/[A-Za-z0-9_+-]{1,32}){0,2}$",
  generatedPassword: "^[A-Za-z0-9]{32}$",
  serverPath: "^/[A-Za-z0-9._/-]{1,255}$",
  proxyUrl: String.raw`^(https?)://(\[[0-9a-f:]{2,39}]|[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._/-]{0,200})?$`,
  // Versions are checked by shape, not by a list (docs/adr/0004): CloudPanel decides what is installed.
  phpVersion: String.raw`^[0-9]{1,2}\.[0-9]{1,2}$`,
  nodejsVersion: "^[0-9]{1,2}$",
  pythonVersion: String.raw`^[0-9]\.[0-9]{1,2}$`,
  // an octal mode without setuid, setgid or sticky bit (a leading 0 is fine) and without world-write: 770, 660, 755, 0644
  fileMode: "^0?[0-7][0-7][0145]$",
  // below the site user's home: "." or segments that do not start with "." (no "..", no dot-files)
  relativePath:
    "^(\\.|[A-Za-z0-9_][A-Za-z0-9._-]{0,63}(/[A-Za-z0-9_][A-Za-z0-9._-]{0,63}){0,15})$",
  cacheTag: "^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$",
} as const;

export type PatternName = keyof typeof SOURCES;

export const RE: Readonly<Record<PatternName, RegExp>> = Object.freeze(
  Object.fromEntries(
    Object.entries(SOURCES).map(([k, v]) => [k, new RegExp(v)]),
  ) as Record<PatternName, RegExp>,
);

export const USER_ROLES = ["admin", "site-manager", "user"] as const;
export const USER_STATUS = ["0", "1"] as const;
// The Update page shows --channel='test'; the default channel's name is not documented.
export const RELEASE_CHANNELS = ["stable", "test"] as const;

export const MAX_DOMAIN_LENGTH = 253;
export const MAX_DOMAIN_LIST = 20;
export const MAX_CACHE_TAGS = 20;

/** Never a site user or a CloudPanel-created account: refused when a tool would create or use them. */
export const RESERVED_SITE_USERS: readonly string[] = Object.freeze([
  "root", "clp", "admin", "administrator", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
  "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "mysql", "redis",
  "nginx", "varnish", "proftpd", "sshd", "ubuntu", "debian", "postgres", "systemd-network",
]);

/** Database accounts a tool never creates: the administrative and system accounts of MySQL, MariaDB and CloudPanel. */
export const RESERVED_DB_USERS: readonly string[] = Object.freeze([
  "root", "mysql", "mysqld", "mariadb", "clp", "cloudpanel", "debian_sys_maint", "mysql_sys", "mariadb_sys", "mysql_session", "mysql_infoschema", "sys",
]);

/** Never targeted by a database tool: system schemas and the panel's own database. */
export const RESERVED_DATABASES: readonly string[] = Object.freeze([
  "mysql", "sys", "information_schema", "performance_schema", "clp", "cloudpanel",
]);

/**
 * Ports an application or a reverse proxy may never be pointed at, whatever a profile allows:
 * databases, caches, queues, container, cluster and admin APIs, the panel and Varnish. Publishing
 * one of these under a domain would be a hole.
 */
export const DENIED_APP_PORTS: readonly number[] = Object.freeze([
  2375, 2376, 2379, 2380, // Docker, etcd
  3306, 3389, 3690, // MySQL, RDP, Subversion
  4369, 4505, 4506, 4646, // Erlang port mapper, Salt, Nomad
  5432, 5601, 5672, 5984, // PostgreSQL, Kibana, AMQP, CouchDB
  6081, 6379, 6443, // Varnish, Redis, Kubernetes API
  8001, 8086, 8200, 8443, 8500, // kubectl proxy, InfluxDB, Vault, the panel, Consul
  9042, 9090, 9092, 9100, 9200, 9300, // Cassandra, Prometheus, Kafka, node exporter, Elasticsearch
  10250, 10255, 11211, 15672, 27017, // kubelet, Memcached, RabbitMQ management, MongoDB
]);

/** System directories a file directory may never be in. */
export const FORBIDDEN_DIR_ROOTS: readonly string[] = Object.freeze([
  "/etc", "/root", "/boot", "/dev", "/proc", "/sys", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/run", "/var/run",
]);

/**
 * Places where other accounts (a site user whose application was hacked, another login) can write, or that are
 * symbolic links into such places. clpctl runs as root and follows symbolic links, so a link planted in such a
 * directory turns a dump into an overwrite of any file, and a certificate or template into a read of any file.
 */
export const SHARED_DIR_ROOTS: readonly string[] = Object.freeze([
  "/home", "/tmp", "/var/tmp", "/var/www", "/var/mail", "/var/spool", "/var/lock", "/var/crash", "/var/lib/php", "/mnt", "/media",
]);

export const underRoot = (path: string, roots: readonly string[]): boolean => roots.some((root) => path === root || path.startsWith(`${root}/`));

export interface PortRange {
  readonly from: number;
  readonly to: number;
}

/** The ports of the usual web applications. A profile may replace this list (appPorts), never widen the denied ports. */
export const DEFAULT_APP_PORTS: readonly PortRange[] = Object.freeze([
  { from: 1337, to: 1337 }, // Strapi
  { from: 2368, to: 2368 }, // Ghost
  { from: 3000, to: 4999 }, // Node.js, Next.js, Express, GraphQL, Angular
  { from: 5000, to: 5000 }, // Flask
  { from: 5173, to: 5173 }, // Vite
  { from: 8000, to: 8199 }, // Django, uvicorn, 8080
]);

/** "3000-3999" or "5173" in the text form used in configuration files and the gate. */
export function portRangeText(range: PortRange): string {
  return range.from === range.to ? String(range.from) : `${range.from}-${range.to}`;
}

export function portRangesText(ranges: readonly PortRange[]): string {
  return ranges.map(portRangeText).join(", ");
}

export function isDomain(value: string): boolean {
  return value.length <= MAX_DOMAIN_LENGTH && RE.domain.test(value);
}

/** The hard floor for an application port: 1024-65535 and not a denied one. */
export function isPortAllowedAtAll(value: number): boolean {
  return (
    Number.isInteger(value) &&
    value >= 1024 &&
    value <= 65535 &&
    !DENIED_APP_PORTS.includes(value)
  );
}

/** An application port: above the hard floor and inside one of the ranges the profile allows. */
export function isAppPort(value: number, ranges: readonly PortRange[]): boolean {
  return isPortAllowedAtAll(value) && ranges.some((range) => value >= range.from && value <= range.to);
}

/** A server path that is absolute, made of safe characters, with no "..", "//", "/./" or trailing slash. */
export function isCleanPath(value: string): boolean {
  if (!RE.serverPath.test(value)) return false;
  if (value.includes("..") || value.includes("//") || value.includes("/./"))
    return false;
  if (value.endsWith("/") || value.endsWith("/.")) return false;
  return true;
}

/** True when `value` is strictly inside one of the allowed directories. */
export function isUnderDirs(value: string, dirs: readonly string[]): boolean {
  return dirs.some(
    (dir) => value.length > dir.length + 1 && value.startsWith(`${dir}/`),
  );
}

/**
 * Each kind of file lives in its own subdirectory of a file directory and has its own extensions, so
 * a file one tool writes (a dump) can never be read by another as something else (a certificate, a
 * vhost template). Only the operator puts files into certs/ and templates/.
 */
export type FileKind = "dump" | "cert" | "template";
export const FILE_KINDS: readonly FileKind[] = Object.freeze(["dump", "cert", "template"] as const);
export const FILE_SUBDIR: Readonly<Record<FileKind, string>> = Object.freeze({ dump: "dumps", cert: "certs", template: "templates" });
export const FILE_EXT_SOURCES: Readonly<Record<FileKind, string>> = Object.freeze({
  dump: String.raw`\.sql(\.gz)?$`,
  cert: String.raw`\.(key|pem|crt|cer|cert|chain|ca-bundle)$`,
  template: String.raw`\.(tpl|conf)$`,
});
const FILE_EXT: Readonly<Record<FileKind, RegExp>> = Object.freeze({
  dump: new RegExp(FILE_EXT_SOURCES.dump),
  cert: new RegExp(FILE_EXT_SOURCES.cert),
  template: new RegExp(FILE_EXT_SOURCES.template),
});
export const FILE_EXT_TEXT: Readonly<Record<FileKind, string>> = Object.freeze({
  dump: ".sql or .sql.gz",
  cert: ".key, .pem, .crt, .cer, .cert, .chain or .ca-bundle",
  template: ".tpl or .conf",
});

/** The directories a kind of file may be in: <fileDir>/dumps, <fileDir>/certs or <fileDir>/templates. */
export function kindDirs(kind: FileKind, fileDirs: readonly string[]): string[] {
  return fileDirs.map((dir) => `${dir}/${FILE_SUBDIR[kind]}`);
}

/** A clean absolute path, strictly inside the kind's subdirectory of a file directory, with one of the kind's extensions. */
export function isKindPath(kind: FileKind, value: string, fileDirs: readonly string[]): boolean {
  return isCleanPath(value) && FILE_EXT[kind].test(value) && isUnderDirs(value, kindDirs(kind, fileDirs));
}

/** Why `value` is not a valid file of this kind, or null. The messages name rules, never the value. */
export function kindPathProblem(kind: FileKind, value: string, fileDirs: readonly string[]): string | null {
  if (!isCleanPath(value)) return "must be a clean absolute path";
  if (!isUnderDirs(value, kindDirs(kind, fileDirs))) {
    return `must be inside ${kindDirs(kind, fileDirs).join(" or ")} (profile fileDirs, subdirectory ${FILE_SUBDIR[kind]}/)`;
  }
  if (!FILE_EXT[kind].test(value)) return `must end with ${FILE_EXT_TEXT[kind]}`;
  return null;
}

export interface ParsedProxyUrl {
  readonly scheme: "http" | "https";
  readonly host: string;
  readonly port: number | null;
  readonly path: string;
}

/** Strict reverse-proxy URL parser. It does not use `new URL`, whose normalisation would hide tricks. */
export function parseProxyUrl(value: string): ParsedProxyUrl | null {
  if (value.length > 300) return null;
  const m = RE.proxyUrl.exec(value);
  if (m === null) return null;
  const scheme = m[1];
  const rawHost = m[2];
  if ((scheme !== "http" && scheme !== "https") || rawHost === undefined)
    return null;
  const host = rawHost.startsWith("[") ? rawHost.slice(1, -1) : rawHost;
  const port = m[4] === undefined ? null : Number(m[4].slice(1));
  if (port !== null && (port < 1 || port > 65535)) return null;
  const path = m[5] ?? "";
  if (path.includes("..") || path.includes("//")) return null;
  return { scheme, host, port, path };
}

/** Why a reverse-proxy URL is refused for a profile, or null: shape, then host, then port (80, 443 or an allowed application port). */
export function proxyUrlProblem(
  value: string,
  allowedHosts: readonly string[],
  appPorts: readonly PortRange[],
): string | null {
  const parsed = parseProxyUrl(value);
  if (parsed === null) {
    return "must be http(s)://host[:port][/path] with only letters, digits and . _ / - in the path";
  }
  if (!allowedHosts.includes(parsed.host)) return `the upstream host must be one of: ${allowedHosts.join(", ")} (profile proxyHosts)`;
  if (parsed.port !== null && parsed.port !== 80 && parsed.port !== 443 && !isAppPort(parsed.port, appPorts)) {
    return `the upstream port must be 80, 443 or an allowed application port: ${portRangesText(appPorts)} (profile appPorts; database, cache and admin ports are never allowed)`;
  }
  return null;
}

export function isAllowedProxyUrl(
  value: string,
  allowedHosts: readonly string[],
  appPorts: readonly PortRange[],
): boolean {
  return proxyUrlProblem(value, allowedHosts, appPorts) === null;
}

/** A purge target for Varnish: "all", a comma list of tags, or one https URL on a host. */
export type ParsedPurge =
  | { readonly kind: "all" }
  | { readonly kind: "tags"; readonly tags: readonly string[] }
  | { readonly kind: "url"; readonly host: string };

export function parsePurge(value: string): ParsedPurge | null {
  if (value === "all") return { kind: "all" };
  if (value.startsWith("https://") || value.startsWith("http://")) {
    const parsed = parseProxyUrl(value);
    if (parsed === null || parsed.port !== null) return null;
    return isDomain(parsed.host) ? { kind: "url", host: parsed.host } : null;
  }
  const tags = value.split(",");
  if (tags.length < 1 || tags.length > MAX_CACHE_TAGS) return null;
  if (!tags.every((tag) => RE.cacheTag.test(tag))) return null;
  // "all" among other tags is ambiguous (everything, or a tag named all?): refuse it
  if (tags.length > 1 && tags.includes("all")) return null;
  return { kind: "tags", tags };
}
