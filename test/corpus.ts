/** Hostile strings: shell metacharacters, option injection, traversal, Unicode tricks, control characters. */
export const HOSTILE: readonly string[] = [
  "", " ", "  ", "-", "--", "-rf", "--force", "-n", "--help", "--", "-o ProxyCommand=id",
  "a.example.com;id", "a.example.com && id", "a.example.com||id", "a.example.com|id", "a.example.com&", "$(id)", "`id`", "${IFS}", "$IFS", "$HOME", "~", "~root",
  "a.example.com\n", "a.example.com\r", "\na.example.com", "a.example.com\r\nrm -rf /", "a.example.com\t", "a.example.com\0", "a\0.example.com", "\0",
  "a.example.com'", 'a.example.com"', "a.example.com\\", "a.example.com#", "a.example.com!", "a.example.com*", "*.example.com", "a.example.com?", "a.example.com<", "a.example.com>",
  "a.example.com(", "a.example.com)", "a.example.com{", "a.example.com}", "a.example.com[", "a.example.com]x", "a.example.com=", "a.example.com,", "a.example.com:",
  "'; id; '", '"; id; "', "' OR '1'='1", "x'$(id)'", "x\\'", "x\\\\", "%s", "%n", "%00", "%0a", "\\x00", "${jndi:ldap://x}",
  "../etc/passwd", "/etc/passwd", "a/../b", "//", "/./", "/var/lib/cloudpanel-mcp-server/../../etc/passwd", "/var/lib/cloudpanel-mcp-server//x", "/var/lib/cloudpanel-mcp-server/",
  "/var/lib/cloudpanel-mcp-server-evil/x.sql", "~/x", "./x", "x/", "x//y", "con", "NUL",
  "ａ.example.com", "a.exаmple.com", "a.example.com\u202e", "a.example.com\u200b", "\ufeffa.example.com", "a.example.com\u0085", "a.ex\u2028ample.com", "é.example.com", "a.example.com ", "ｘ",
  "\u001b[31mred\u001b[0m", "\u001b]0;title\u0007", "\u0007", "\u007f", "\u0080",
  "A".repeat(300), "a.".repeat(130) + "com", "9".repeat(70),
  "A.EXAMPLE.COM", "example", "example.", ".example.com", "a..example.com", "-a.example.com", "a-.example.com", "a_b.example.com",
  "x --force", "x=--force", "x --domainName=y", "x\n--force", "--domainName=evil.example.com",
  "http://user@127.0.0.1", "http://127.0.0.1@evil.example.com", "http://127.0.0.1:80@evil.example.com/", "http://127.0.0.1:2375", "http://127.0.0.1:0", "http://127.0.0.1:65536",
  "http://[::1", "http://::1", "file:///etc/passwd", "ftp://127.0.0.1", "http://", "https://", "http://127.0.0.1/..", "http://127.0.0.1//x", "http://127.0.0.1/%2e%2e",
];

/** Characters that may never appear in an accepted value (space is checked per pattern). */
export const FORBIDDEN_IN_VALUES = /['"`\\$;&|<>()*?{}~#!\n\r\t\0]|[^\x20-\x7e]/;

/** The only characters an argv token passed to clpctl may contain (the engine's end-to-end invariant). */
export const SAFE_TOKEN = /^[A-Za-z0-9 ._:/,@+=[\]-]*$/;
