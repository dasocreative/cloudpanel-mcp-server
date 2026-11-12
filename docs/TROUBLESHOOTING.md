# Troubleshooting

First run `npx -y cloudpanel-mcp-server@0.1.0 --check-config`, then `--check-connection`, in a terminal: they say what is wrong in plain words.

| Symptom | Cause and fix |
| ------- | ------------- |
| The client shows the server as failed, or `configuration error: ...` | Run `npx -y cloudpanel-mcp-server@0.1.0 --check-config`, then `--check-connection`, in a terminal: they say what is wrong. A misspelt `CLOUDPANEL_MCP_*` name is refused on purpose. |
| `Host key verification failed` | Log in once by hand (`ssh -i ~/.ssh/id_ed25519_cloudpanel cloudpanel-mcp@203.0.113.10`, answer `yes`; the gate then refuses the session, that is fine) so the host is in `known_hosts`; the server never accepts an unknown host. |
| `Permission denied (publickey)` | Wrong user or key, or the public key is not in the account's `authorized_keys` (run the setup script again with `--key`). An `AllowUsers` line in `sshd_config` must name the account. |
| The call hangs and times out | A prompt nobody can answer: a key passphrase (load the key into `ssh-agent`, or use the dedicated key without one) or a host-key question. |
| `sudo: a password is required` | The sudoers line is missing, has another path, or names another user: run the setup script again. |
| "no human approval is possible ..." | Your client does not support MCP elicitation forms. Run the printed command yourself, or use a client that does; for *writes only* you may set `approval.write` to `"client"`. |
| "this server's clpctl does not list the command ..." | Your CloudPanel release lacks it (e.g. user commands before 2.3.0). `clp_list_commands` shows what it has. |
| "does not allow write tools" | Add `write` (or `destructive`, `admin`) to `allow` for that profile and restart the client. The gate's ceiling must allow it too (`--allow` of the setup script). |
| `cloudpanel-mcp-gate: refused: ...` | The gate stopped a call its settings do not allow (class ceiling, a protected target, a file outside its directories): see [The gate](SECURITY-MODEL.md#the-gate). |
| "rate limit reached" | Wait, or raise `rateLimits` for that profile (the defaults are deliberately low for destructive and admin). "too many approval questions" is the `ask` limit: the human may be put 30 questions per 10 minutes by default, answered or not. |
| "file must be inside ... (profile fileDirs, subdirectory dumps/)" | Each kind of file lives in its own subdirectory of a file directory: `dumps/` (`*.sql`, `*.sql.gz`), `certs/` (`*.key`, `*.pem`, `*.crt`, ...), `templates/` (`*.tpl`, `*.conf`). `clp_server_info` shows the exact paths. |
| "Vhost Template cannot be empty" | CloudPanel reads the template file as its own account: make `templates/` `0755` and the file `0644`, both root-owned. |
| "appPort must be one of the ports this profile allows" | Add the port to `appPorts` in the profile (database, cache and admin ports are refused whatever you list). |
| A password file already exists / where are my passwords? | `<state dir>/secrets/<profile>/` (mode `0700`). Each call writes a new file; a failed call renames it `*.failed.json`. |
| Let's Encrypt fails | DNS records for every name must already point at the server; the call can take up to 10 minutes. |
| `db:delete` leaves the database user | Observed on CloudPanel 2.5.4: the user goes when the site is deleted. |
| Windows: ssh not found | Install the OpenSSH client feature. Connection sharing is not used on Windows. |
