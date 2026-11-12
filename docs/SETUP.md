# Setup in detail

## The steps

Replace `203.0.113.10` with your server's address (or an alias of your `~/.ssh/config`) in the commands below.

> **Before the first release is on npm** (now): `git clone` this repository, `npm ci && npm run build`, and use `node /absolute/path/to/dist/index.js` wherever
> `npx -y cloudpanel-mcp-server@0.1.0` appears.

### 1. Make a key for the assistant (your computer)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_cloudpanel -N "" -C ai-assistant
```

No passphrase, because your AI client starts the server in the background where nobody can type one. That is acceptable here because step 2 pins this key to
the gate: it can run CloudPanel's commands and nothing else, never a shell. (Prefer a passphrase? Load the key into `ssh-agent` before you start the client.)

### 2. Prepare the server (one command)

If you can log in as `root`:

```bash
npx -y cloudpanel-mcp-server@0.1.0 --print-server-setup | ssh root@203.0.113.10 "bash -s -- --key '$(cat ~/.ssh/id_ed25519_cloudpanel.pub)' --allow write"
```

If you log in with a sudo account instead:

```bash
npx -y cloudpanel-mcp-server@0.1.0 --print-server-setup > cloudpanel-mcp-setup.sh
scp cloudpanel-mcp-setup.sh you@203.0.113.10:
ssh -t you@203.0.113.10 "sudo bash cloudpanel-mcp-setup.sh --key '$(cat ~/.ssh/id_ed25519_cloudpanel.pub)' --allow write"
```

The script ([read it](../hardening/cloudpanel-mcp-setup.sh), or `npx -y cloudpanel-mcp-server@0.1.0 --print-server-setup | less`) changes no site, no CloudPanel
setting, no firewall and no SSH setting. It:

1. creates the account `cloudpanel-mcp` (no password: key login only);
2. allows it exactly one program as root, `clpctl` (one sudoers line, checked by `visudo`);
3. creates the root-owned directories for database dumps, certificates and vhost templates (`/var/lib/cloudpanel-mcp-server/`);
4. installs [the gate](SECURITY-MODEL.md#the-gate) and pins your key to it;
5. warns you if your SSH server would refuse the account (an `AllowUsers` line, for example);
6. tests the whole chain as the new account and prints the next command.

`--allow` is the most the key may ever do on this server, whatever a client asks: `read` (only look), `write` (also add and update: the default) or `all` (also
delete and manage panel users; each call still needs your typed approval). Other options: `--inventory` (the [site list](#inventory-optional-unofficial) helper),
`--user <name>`, `--dry-run`, `--help`. Running it again is safe. On Windows, run this step from Git Bash or WSL. Prefer to type it yourself?
[docs/MANUAL-SETUP.md](#preparing-a-server-by-hand) has the same steps by hand.

### 3. Save the connection (your computer)

```bash
npx -y cloudpanel-mcp-server@0.1.0 --init --host 203.0.113.10 --allow write
```

This writes the configuration file (it prints where; never over an existing one) and checks the connection. You should see:

```
profile default (ssh -i /home/you/.ssh/id_ed25519_cloudpanel cloudpanel-mcp@203.0.113.10): ok - sudo -n /usr/bin/clpctl answered with 28 commands
```

If not, the line below it says what to fix (see also [Troubleshooting](TROUBLESHOOTING.md)); `--check-connection` checks again. Leave out `--allow write` to start
read-only; add `destructive` and `admin` later, in the file, if you need them.

### 4. Connect your AI agent

See [CLIENTS.md](CLIENTS.md): one command or one small block per client.

### 5. Try it

Ask your assistant:

> Call `clp_server_info` and tell me what my CloudPanel server offers.

Then, with `--allow write`: *"Add a static site test.example.com with the site user test"*. Your client shows the approval form with the exact command; accept it,
and the site exists. The site user's password is in a private file on your machine (the answer gives its path), never in the chat.

## Preparing a server by hand

The [setup script](../hardening/cloudpanel-mcp-setup.sh) (`cloudpanel-mcp-server --print-server-setup`) does all of this in one run and tests it. These are the
same steps, for those who prefer to type them, to adapt them, or to understand what the script does. Run them as root (or with `sudo`) on the CloudPanel server.

### 1. An account for the assistant

```bash
sudo useradd --create-home --shell /bin/bash --user-group cloudpanel-mcp   # no password: only a key can log in
```

You can reuse an existing account (`deploy`, your own), but a dedicated one is safer: with the gate (step 4), nothing else should ever log in with it.

### 2. One program as root

```bash
sudo visudo -f /etc/sudoers.d/cloudpanel-mcp-server
```

containing a single line (check the path with `command -v clpctl`; it is `/usr/bin/clpctl` on current releases):

```
cloudpanel-mcp ALL=(root) NOPASSWD: /usr/bin/clpctl
```

### 3. Directories for dumps, certificates and templates

Each kind of file has its own subdirectory, so a dump the assistant exports can never be read back as a certificate or as a vhost template, and the server never
lets the assistant name a file anywhere else:

```bash
sudo install -d -m 0755 -o root -g root /var/lib/cloudpanel-mcp-server
sudo install -d -m 0700 -o root -g root /var/lib/cloudpanel-mcp-server/dumps /var/lib/cloudpanel-mcp-server/certs
sudo install -d -m 0755 -o root -g root /var/lib/cloudpanel-mcp-server/templates
```

The assistant writes and reads database dumps (`*.sql`, `*.sql.gz`) in `dumps/`. **You** put certificates (`*.key`, `*.pem`, `*.crt`, ...) into `certs/` and
vhost templates (`*.tpl`, `*.conf`) into `templates/`, as root; the assistant cannot create files there. `vhost-template:add` reads its file as CloudPanel's own
account, not as root (observed on 2.5.4), so `templates/` is `0755` and each template file `0644` (`sudo install -m 0644 my.tpl /var/lib/cloudpanel-mcp-server/templates/`).

They must stay **root-owned**: `clpctl` runs as root and follows symbolic links, so a directory another account can write in lets that account turn a dump into the
overwrite of any file.

### 4. The gate, and the key pinned to it

The gate is a script that limits the key to what this project can send: the same commands, the same value types and a ceiling on classes. It is generated from
the tool catalogue ([hardening/cloudpanel-mcp-gate.sh](../hardening/cloudpanel-mcp-gate.sh)).

```bash
sudo install -o root -g root -m 0755 hardening/cloudpanel-mcp-gate.sh /usr/local/sbin/cloudpanel-mcp-gate.sh
```

Read its settings block (class ceilings, file directories, application ports, proxy hosts, protected targets) and keep them equal to the profile's. By default it
allows read and write commands and **refuses destructive and admin ones**; raise `ALLOW_DESTRUCTIVE` / `ALLOW_ADMIN` only if you also enable the class in the profile.

On your machine, make the key (no passphrase: the MCP client starts the server where nobody can type one; the gate is what makes that acceptable):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_cloudpanel -N "" -C ai-assistant
```

On the server, pin it to the gate. Root owns the file, so the account cannot add a key of its own that skips the gate:

```bash
sudo install -d -o root -g root -m 0755 /home/cloudpanel-mcp/.ssh
echo 'command="/usr/local/sbin/cloudpanel-mcp-gate.sh",restrict ssh-ed25519 AAAA... ai-assistant' | sudo tee /home/cloudpanel-mcp/.ssh/authorized_keys
sudo chmod 0644 /home/cloudpanel-mcp/.ssh/authorized_keys
```

If your `sshd` configuration has an `AllowUsers` line, add `cloudpanel-mcp` to it (`sshd -t && systemctl reload ssh`).

### 5. Test

```bash
ssh -i ~/.ssh/id_ed25519_cloudpanel cloudpanel-mcp@203.0.113.10 'sudo -n /usr/bin/clpctl'   # prints CloudPanel's command listing
ssh -i ~/.ssh/id_ed25519_cloudpanel cloudpanel-mcp@203.0.113.10 'ls'                        # cloudpanel-mcp-gate: refused: ...
```

Then continue with [step 3](#3-save-the-connection-your-computer) (`--init`).

### Without the gate

Leave out step 4's gate and pin the key with `restrict` only. Whoever holds the key is then as powerful as the sudoers line: every `clpctl` command, including
deleting sites and adding administrators. Not recommended; if you do it, keep a passphrase on the key and load it into `ssh-agent`.

### Site-user logins

`system:permissions:reset` and `varnish-cache:purge` are CloudPanel *site-user* commands: they run as that user, over an ssh login you set up for the user (an SSH
key in the site user's settings in the panel) and map in `siteUserAccess`. For those logins use a copy of the gate with `SCOPE=siteuser` (it then accepts only the
two site-user commands, without sudo; `PROTECT_SITE_USERS` then names the accounts whose key it must refuse, since their commands carry no user name).

## Inventory (optional, unofficial)

`clpctl` cannot list sites. [inventory/cloudpanel-mcp-inventory](../inventory/cloudpanel-mcp-inventory) is a small POSIX shell script that reads the NGINX
vhost files CloudPanel writes and prints a JSON list (domain, aliases, a *guess* of the site type, site user, root, certificate expiry). It is **not part of
CloudPanel**, takes no arguments, writes nothing and prints only values that passed a strict pattern. The setup script installs it with `--inventory` (it adds the
one sudoers line and `ALLOW_INVENTORY=1` in the gate); by hand, see the comment at the top of the script. Then set `"inventory": true` in the profile; the tool
`clp_inventory_sites` appears.

## Remove it from a server

As root on the server:

```bash
rm -f /etc/sudoers.d/cloudpanel-mcp-server /usr/local/sbin/cloudpanel-mcp-gate.sh /usr/local/sbin/cloudpanel-mcp-inventory
userdel -r cloudpanel-mcp           # the account and its home (not if you reused an account of your own)
rm -rf /var/lib/cloudpanel-mcp-server   # after you have kept the dumps you need
```

On your computer: remove the client registration, the configuration file (`--check-config` prints where) and the state directory (audit log, password files),
and delete `~/.ssh/id_ed25519_cloudpanel*`.
