# Configuration

The server reads its configuration once, at start, from a JSON file (`--init` writes one for a server) or, when there is no file, from `CLOUDPANEL_MCP_*`
variables (a variable that is misspelt makes it refuse to start instead of being ignored). A configuration that others can write is refused.
`--check-config` prints what yours means (no secrets); `--check-connection` logs in and runs the read-only command listing.

The file is `CLOUDPANEL_MCP_CONFIG`, or `~/.config/cloudpanel-mcp-server/config.json` (Linux), `~/Library/Application Support/cloudpanel-mcp-server/config.json`
(macOS), `%APPDATA%\cloudpanel-mcp-server\config.json` (Windows). Create it with `chmod 600`.

```jsonc
{
  "profiles": {
    "my-server": {
      "ssh": { "host": "203.0.113.10", "user": "cloudpanel-mcp", "port": 22, "identityFile": "~/.ssh/id_ed25519_cloudpanel" },  // or "local": true
      "elevation": "sudo",                 // "sudo" (default) or "none" when the account is root
      "clpctlPath": "/usr/bin/clpctl",
      "allow": ["write"],                  // reading is always on; add "destructive" and "admin" deliberately
      "approval": { "write": "ask" },      // "ask" (default) or "client"; destructive and admin always ask a human
      "protect": {
        "domains": ["panel.example.com", "*.shop.example.com"],   // exact, or *.suffix (also the apex); www is ignored
        "siteUsers": [], "databases": [], "panelUsers": ["owner"]
      },
      "fileDirs": ["/var/lib/cloudpanel-mcp-server"],   // its subdirectories dumps/, certs/, templates/ are used; ROOT-OWNED, see below (>= 2 levels; not /etc, /usr ... nor /home, /tmp, /var/www ...)
      "proxyHosts": ["127.0.0.1", "localhost", "::1"],  // where a reverse-proxy site may point
      "appPorts": [1337, 2368, "3000-4999", 5000, 5173, "8000-8199"],   // ports for Node.js/Python apps and proxy upstreams (this is the default); 3306, 6379, 8443 ... never
      "siteUserAccess": { "shop": "my-server-shop" },   // ssh alias that logs in AS the site user, for permissions reset and Varnish purge
      "inventory": false,                               // the optional, unofficial "list the sites" script
      "rateLimits": { "write": [20, 10], "destructive": [3, 10], "admin": [5, 10], "ask": [30, 10] },   // [calls, minutes]; "ask" = approval questions put to the human, answered or not
      "timeoutsSeconds": { "default": 120, "letsEncrypt": 600, "db": 600 }
    }
  },
  "defaultProfile": "my-server"
}
```

Several profiles each get their own safety level; with more than one and no `defaultProfile`, every tool call must name its `profile`. To add a server, run the
setup script there, then `--init --host <its address> --profile <a name>`: the file exists, so it changes nothing and prints the block to paste into `profiles`.

**Without a file**, the variables below make one profile; that is handy in a client configuration (`"env": { "CLOUDPANEL_MCP_SSH_HOST": "203.0.113.10",
"CLOUDPANEL_MCP_SSH_USER": "cloudpanel-mcp", "CLOUDPANEL_MCP_SSH_IDENTITY_FILE": "~/.ssh/id_ed25519_cloudpanel" }`). When the file exists, it wins.

**File directories must be root-owned.** `clpctl` runs as root and follows symbolic links. If any account other than root can write in `<fileDir>`, `<fileDir>/dumps`,
`<fileDir>/certs` or `<fileDir>/templates` (a site user whose application was hacked, the SSH account itself), a link planted there turns a dump into the
overwrite of any file, and a certificate or template into the read of any file. So create them as root, mode `0700` or `0755` (the commands in step 2), and keep
them there. The server cannot check this on the remote machine; it does refuse the places where other accounts usually can write (`/home`, `/tmp`, `/var/tmp`,
`/var/www`, `/var/mail`, `/mnt`, `/media`) and the system directories. A throw-away test server may set `"allowUntrustedFileDirs": true` to use them; the
profile then carries a warning.

The ssh connection-sharing sockets in the state directory are kept per login (alias, user, port and key), so a profile with a strict key and another with a
laxer key for the same machine never share a connection.

| Variable | Meaning |
| -------- | ------- |
| `CLOUDPANEL_MCP_CONFIG` | path of the JSON file |
| `CLOUDPANEL_MCP_STATE_DIR` | audit log, password files, ssh sockets (default per platform, mode `0700`) |
| `CLOUDPANEL_MCP_PROFILE` | profile name for the variable quick start (default `default`) |
| `CLOUDPANEL_MCP_SSH_HOST` / `_SSH_USER` / `_SSH_PORT` / `_SSH_IDENTITY_FILE` / `_SSH_CONFIG_FILE` | where to connect (an alias is the simplest) |
| `CLOUDPANEL_MCP_LOCAL` | `1`: this machine is the CloudPanel host |
| `CLOUDPANEL_MCP_ELEVATION` | `sudo` or `none` |
| `CLOUDPANEL_MCP_CLPCTL_PATH` | default `/usr/bin/clpctl` |
| `CLOUDPANEL_MCP_ALLOW` | comma list of `write`, `destructive`, `admin` |
| `CLOUDPANEL_MCP_APPROVAL_WRITE` | `ask` or `client` |
| `CLOUDPANEL_MCP_PROTECT_DOMAINS` / `_PROTECT_SITE_USERS` / `_PROTECT_DATABASES` / `_PROTECT_PANEL_USERS` | comma lists |
| `CLOUDPANEL_MCP_FILE_DIRS` / `_PROXY_HOSTS` / `_APP_PORTS` | comma lists (ports as `3000` or `3000-3999`) |
| `CLOUDPANEL_MCP_INVENTORY` / `_INVENTORY_COMMAND` | `1` to enable the inventory, and its path |

## Several servers, and the CloudPanel host itself

One profile per server. To run on the CloudPanel host (so nothing needs ssh), use `"local": true`; if the process is not root, `elevation: "sudo"` runs
`sudo -n clpctl` as above. A client on your laptop can still reach it by starting the server over ssh: `command: "ssh", args: ["my-server", "cloudpanel-mcp-server"]`.

## Site-user commands

`system:permissions:reset` and `varnish-cache:purge` are CloudPanel *site-user* commands. They run as that user, over an ssh login you set up for the user
(an SSH key in the site user's settings in the panel) and map in `siteUserAccess`. Without an entry the tools are not listed.
