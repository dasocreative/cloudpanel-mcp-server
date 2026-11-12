# CloudPanel `clpctl` command reference

This is the reference the tool catalogue is built from. Source priority for every fact:

1. the **official CloudPanel v2 documentation** (<https://www.cloudpanel.io/docs/v2/>), read in full on 2026-11-05
   (87 pages; the newest changelog entry is **v2.5.4, 2026-07-01**);
2. a **live observation** on a real server, recorded with date, product version and operating system;
3. third-party material, always marked unverified.

Status legend used in every table:

| Mark | Meaning |
| ---- | ------- |
| **D** | Documented on the official page named in the *Source* column. |
| **O** | Observed on a real CloudPanel server (see [Observations](#observations)). Not in the docs, or the docs are silent. |
| **U** | Unverified: inferred, or from third-party material. Never relied on without a live check. |

Page keys (all under `https://www.cloudpanel.io/docs/v2/`):
**R** `cloudpanel-cli/root-user-commands/` · **S** `cloudpanel-cli/site-user-commands/` · **C** `changelog/` ·
**DB** `frontend-area/databases/` · **SEC** `admin-area/security/` · **UP** `update/` · **ST** `frontend-area/settings/` ·
**ADD** `frontend-area/add-site/` · **V** `frontend-area/vhost/` · **TLS** `frontend-area/tls/` · **FS** `frontend-area/security/` ·
**TS** `technology-stack/` · **PY** `python/deployment/uwsgi/` · **VC** `frontend-area/varnish-cache/settings/`.

## 1. How the CLI behaves

| Fact | Source | Status |
| ---- | ------ | ------ |
| The binary is `/usr/bin/clpctl` (a fix for its shebang is in v2.5.0, bug #476). | C | D |
| Root commands are run as the root user, over SSH or on the host. | R, SEC, apps pages ("as root user") | D |
| Site-user commands (`system:permissions:reset`, `varnish-cache:purge`, `db:export`, `db:import`) are run by logging in over SSH as the **site user**. | S, DB | D |
| `clpctl` with no argument lists the commands ("Run `clpctl` to see all available commands"). | DB | D |
| `clpctl` with no argument prints a usage listing: group headings (`db`, `site`, ...), `// comment` lines, and one ` clpctl <name> --option=value ...` example line per command. Recorded over SSH without a terminal on CloudPanel 2.5.4: plain text, exit status 0, 28 commands. (An earlier note of ANSI colours comes from a run with a terminal.) | – | O |
| `clpctl list`, `clpctl help` and `clpctl --help` do **not** exist on the observed server: an unknown command prints a JSON log line (`message`, `context`, `level_name`) followed by a human block, and exits non-zero. | – | O |
| Errors (validation, "already exists") come as a JSON log line on stdout (keys `message`, `context`, `level_name`), followed by a human block. Validation messages look like `databaseName: This value is not valid.`. | – | O |
| Options are written `--name=value`; values with special characters are single-quoted in every example. Special characters in passwords work from v2.3.0 (bug #284). | R, C | D |
| Domain names are normalised by the CLI from v2.3.0 (bug #278). | C | D |
| Exit codes, defaults, required versus optional options, `--help`, a JSON output mode and a version flag are **not documented**. Nothing on the CLI page is labelled required; only `--subjectAlternativeName` and `--certificateChain` are called optional, `--force` by wording. | R | D (silence) |
| A `clpctlWrapper` command exists for CloudPanel's own `sudo` rule (a privilege-escalation fix in v2.5.0 concerned it). It is not a documented user command and this project never calls it. | C | D |
| There is **no public API, API token or webhook** in the v2 documentation: the CLI is the only documented automation interface (plus `clp-update` and the separate DPLOY deploy tool). Blog posts hinting at tokens or at commands such as `system:services:status`, `log:show`, `db:connection:verify` are **not** in the docs. | index, TS, UP | D (silence) / U (blogs) |

## 2. Command index

28 commands are known by name from the documentation and the observed server. "Tool" is the MCP tool of this project
(see [SPEC.md](SPEC.md)); "none" means no tool, with the reason in [§6](#6-commands-without-a-tool).

<!-- machine-checked by test/docs.test.ts: one row per command, first column is the command in backticks -->

| Command | Run as | Source | Since | Status | Tool |
| ------- | ------ | ------ | ----- | ------ | ---- |
| `cloudflare:update:ips` | root | R | – | D | `clp_cloudflare_update_ips` |
| `cloudpanel:enable:basic-auth` | root | R, SEC | – | D | `clp_cloudpanel_enable_basic_auth` |
| `cloudpanel:disable:basic-auth` | root | R, SEC | – | D | `clp_cloudpanel_disable_basic_auth` |
| `cloudpanel:set:release-channel` | root | UP | – | D (UP page), O | `clp_cloudpanel_set_release_channel` |
| `db:show:master-credentials` | root | R, DB | – | D | `clp_db_show_master_credentials` |
| `db:add` | root | R | – | D, O | `clp_db_add` |
| `db:delete` | root | – | – | O only | `clp_db_delete` |
| `db:export` | root, site user | R, S, DB | – | D | `clp_db_export` |
| `db:import` | root, site user | R, S, DB | – | D | `clp_db_import` |
| `db:backup` | `clp` (cron) | DB | – | D (cron line only) | none |
| `lets-encrypt:install:certificate` | root | R | – | D | `clp_lets_encrypt_install_certificate` |
| `site:add:nodejs` | root | R | – | D | `clp_site_add_nodejs` |
| `site:add:static` | root | R | – | D, O | `clp_site_add_static` |
| `site:add:php` | root | R, application pages | – | D | `clp_site_add_php` |
| `site:add:python` | root | R | – | D | `clp_site_add_python` |
| `site:add:reverse-proxy` | root | R | v2.2.1 (feature) | D, O | `clp_site_add_reverse_proxy` |
| `site:install:certificate` | root | R | **v2.3.0** | D | `clp_site_install_certificate` |
| `site:delete` | root | R | – | D, O | `clp_site_delete` |
| `user:add` | root | R | **v2.3.0** | D | `clp_user_add` |
| `user:delete` | root | R | **v2.3.0** | D | `clp_user_delete` |
| `user:list` | root | R | **v2.3.0** | D | `clp_user_list` |
| `user:reset:password` | root | R | – | D | `clp_user_reset_password` |
| `user:disable:mfa` | root | R, account page | – | D | `clp_user_disable_mfa` |
| `vhost-templates:import` | root | R | – | D | `clp_vhost_templates_import` |
| `vhost-templates:list` | root | R | – | D | `clp_vhost_templates_list` |
| `vhost-template:add` | root | R | – | D | `clp_vhost_template_add` |
| `vhost-template:delete` | root | R | – | D | `clp_vhost_template_delete` |
| `vhost-template:view` | root | R | – | D | `clp_vhost_template_view` |
| `system:permissions:reset` | site user (also listed for root) | S | – | D, O | `clp_system_permissions_reset` |
| `varnish-cache:purge` | site user (not in the root listing) | S | v2.1.0 (Varnish) | D | `clp_varnish_cache_purge` |

"Since": only `user:add`, `user:delete`, `user:list` and `site:install:certificate` have a stated version (v2.3.0, 2023-06-06). Every
other command is "unstated" (the first release, v2.0.0, is "Initial Release" with no list). No option history is published.
An older v2 therefore may lack commands: this project detects them at start-up instead of assuming ([SPEC.md](SPEC.md), feature detection).

## 3. Root commands: options

No option is labelled required in the docs. The "Expected" column is what the examples show; the live usage listing (section 1) is
the authority at run time, and the optional ones may be missing from it.

### 3.1 Sites

| Command | Options (examples as in the docs) | Expected | Notes | Status |
| ------- | --------------------------------- | -------- | ----- | ------ |
| `site:add:php` | `--domainName=www.domain.com --phpVersion=8.4 --vhostTemplate='Generic' --siteUser=john --siteUserPassword='!secretPassword!'` | all five | The vhost template must be one of `vhost-templates:list`. Creates site user `/home/<siteUser>`, document root `/home/$siteUser/htdocs/$domainName/$rootDirectory`. PHP 7.1–8.5 on every supported OS (8.5 since v2.5.3; 8.4 since v2.5.0; 8.3 since v2.4.0; 8.2 since v2.2.0). | D (R, TS, C) |
| `site:add:nodejs` | `--domainName --nodejsVersion=22 --appPort=3000 --siteUser --siteUserPassword` | all five | Page R lists 22, 20, 18, 16, 14, 12; **24** is in TS and C (v2.5.4). Versions are managed with nvm. "If you need another version, you can change the version afterward" (UI only). | D (R, TS, C) |
| `site:add:python` | `--domainName --pythonVersion=3.9 --appPort=8080 --siteUser --siteUserPassword` | all five | The default is the OS's Python (TS: 22.04 → 3.10, Debian 12 → 3.11, 24.04 → 3.12, Debian 13 → 3.13, 26.04 → 3.14); R says Ubuntu 22.04 needs 3.10 although its own example shows 3.9. More versions can be installed (guide `python/guides/adding-a-python-version/`), so the set is **not** closed. | D; the OS defaults D (TS) |
| `site:add:static` | `--domainName --siteUser --siteUserPassword` | all three | – | D, O |
| `site:add:reverse-proxy` | `--domainName=www.domain.com --reverseProxyUrl='http://127.0.0.1:8000' --siteUser --siteUserPassword` | all four | The upstream URL is a plain URL; its allowed hosts are not documented. Reverse proxy exists since v2.2.1. | D, O |
| `site:delete` | `--domainName=www.domain.com [--force]` | `--domainName` | Without `--force` it asks for `yes` on the terminal. The UI says deleting "will permanently remove all site files, databases, users, and configs, and they will be non-recoverable" (ST). Leftover fixes: #338 certificate (v2.4.0), #359 PM2 app (v2.4.0), #758 user crontab (v2.5.4). | D |
| `site:install:certificate` | `--domainName --privateKey=/path/private.key --certificate=/path/cert.crt [--certificateChain=/path/chain.crt]` | first three | File paths read **by root**. The chain is optional. Since v2.3.0. | D |
| `lets-encrypt:install:certificate` | `--domainName=www.domain.com [--subjectAlternativeName=domain1.com,www.domain1.com]` | `--domainName` | "www.domain.com" also covers "domain.com" and vice versa; valid DNS records are required for every name. Since v2.4.1 issuance is first tested against Let's Encrypt staging (C). | D |

**WordPress** is created only by the UI wizard (domain, title, admin user, password, e-mail; manual site user since v2.3.0). There is **no
`site:add:wordpress`** command. There are no other site types: applications (Laravel, Symfony, Magento, ...) are PHP sites with a vhost
template; Ghost and Strapi are Node.js sites; Python apps use uWSGI (PY).

### 3.2 Databases

| Command | Options | Notes | Status |
| ------- | ------- | ----- | ------ |
| `db:add` | `--domainName=www.domain.com --databaseName=my-database --databaseUserName=john --databaseUserPassword='!secretPassword!'` | Adds a database and its user to a site. Live: an **underscore in `databaseName` is rejected** (`databaseName: This value is not valid.`), letters and digits are accepted, a hyphen was not reported invalid; an existing user gives `databaseUserName: This value already exists.`. The docs' own example name has a hyphen. | D, O |
| `db:delete` | `--databaseName` | Not in the docs. Earlier recording (O4): prints `Confirm to delete the database: X (yes/no): ` on stderr, but goes on and deletes when stdin is closed, then prints `The database X has been deleted.` It leaves the database **user** (removed when the site is deleted). The tool counts the call as done only when that last line is there; otherwise it answers "not confirmed". The live contract test checks the effect (the name can be used again). | O |
| `db:export` | `--databaseName=my-database --file=dump.sql.gz` | `.sql.gz` gzips, `.sql` is plain. Uses `mysqldump`. The docs run it as the **site user** from the directory where the dump should go (a bare file name). The root form is on page R. Absolute paths: unverified. | D; paths U |
| `db:import` | `--databaseName --file=dump.sql[.gz]` | "Go to the database dump's directory". Overwrites data. The docs warn: do not use phpMyAdmin for export or import. | D; paths U |
| `db:show:master-credentials` | – | Prints the master database host, user, **password** and port and a "Connect Command". The output is shown as an image in the docs. | D |
| `db:backup` | `--ignoreDatabases='db1,db2' --retentionPeriod=7` | Appears only in the nightly cron line (`15 3 * * * clp /usr/bin/bash -c "/usr/bin/clpctl db:backup ..."` in `/etc/cron.d/clp`, 3:15 AM, 7 days, dumps in `/home/$site-user/backups/`). Not a user command. | D (cron line) |

There is no CLI to add or delete extra database **users**, to list databases, or to manage database servers (UI: Databases, Admin → Settings → Database Servers).

### 3.3 Users and the panel

| Command | Options | Notes | Status |
| ------- | ------- | ----- | ------ |
| `user:add` | `--userName='john.doe' --email='john.doe@domain.com' --firstName='John' --lastName='Doe' --password='!password!' --role='admin' --timezone='UTC' --status='1' [--sites='domain.com,domain.io']` | Roles in the examples: `admin`, `site-manager`, `user` (the UI also names "Site Manager" and "User"). `--sites` is shown only with role `user`. `--status='1'` is the only status shown; `--timezone='UTC'` the only timezone. Since v2.3.0. | D |
| `user:delete` | `--userName='john.doe'` | Since v2.3.0. **Observed on 2.5.4:** asks "Confirm to delete the user: X (yes/no):" and, with no terminal, does nothing and exits 0; `--force` (not in the usage listing) deletes. | D, O |
| `user:list` | – | Since v2.3.0. The output is a table (an image in the docs). | D |
| `user:reset:password` | `--userName=john.doe --password='!newPassword!'` | – | D |
| `user:disable:mfa` | `--userName=john.doe` | Disables two-factor authentication ("if you can't log in"). | D |
| `cloudpanel:enable:basic-auth` | `--userName=john.doe --password='password123'` | Basic Auth **in front of the panel** (port 8443), as an extra layer when 8443 cannot be closed. Not per-site. | D |
| `cloudpanel:disable:basic-auth` | – | – | D |
| `cloudpanel:set:release-channel` | `--channel='test'` | Only `test` is shown (test releases = early access, may be experimental, "some may not ever reach the stable release"); then `clp-update` (a separate root script, never run by this project). The default channel's name is not documented. | D (UP), O |
| `cloudflare:update:ips` | – | Runs every day at 6 AM from cron; writes `/etc/nginx/cloudflare/ips`, which a site's vhost includes when "Allow traffic from Cloudflare only" is enabled. | D |

### 3.4 Vhost templates

| Command | Options | Notes | Status |
| ------- | ------- | ----- | ------ |
| `vhost-templates:list` | – | Lists the templates a PHP site can use. Names are versioned (`Laravel 13`, `Symfony 8`, `Drupal 11`, `Joomla 6`, `Magento 2`, `Nextcloud 34`, `TYPO3 14`, `Generic`, `My Application`, ...): always take them from this list. | D |
| `vhost-templates:import` | – | Run every night; updates the templates from <https://github.com/cloudpanel-io/vhost-templates>. | D |
| `vhost-template:add` | `--name='My Application' --file=/tmp/template.tpl` | `--file` is a **path or a remote URL** (a gist is the docs' example). The file is an NGINX server block; the first line `#{"rootDirectory":"public","phpVersion":"8.4"}` prefills the site wizard. Documented placeholders: `{{ssl_certificate_key}} {{ssl_certificate}} {{server_name}} {{root}} {{nginx_access_log}} {{nginx_error_log}} {{settings}} {{php_fpm_port}} {{php_settings}}`, plus `{{varnish_proxy_pass}}` (Varnish developer guide) and `{{app_port}}` (PY). Overwrite behaviour and validation of the file are not documented. | D |
| `vhost-template:view` | `--name='My Application'` | – | D |
| `vhost-template:delete` | `--name='My Application'` | – | D |

## 4. Site-user commands

Run as the site user over SSH (the user's login, not root). Page S.

| Command | Options | Notes | Status |
| ------- | ------- | ----- | ------ |
| `system:permissions:reset` | `--directories=770 --files=660 --path=.` | "Reset the permissions of a file or directories." `--path` is relative to the current directory in the example. | D |
| `varnish-cache:purge` | `--purge=all` · `--purge='tag1,tag2'` · `--purge='https://www.domain.com/site.html'` | Purge everything, cache tags or one URL (a local PURGE to `127.0.0.1:6081` with header `X-Cache-Tags`, VC). | D |
| `db:export`, `db:import` | as in §3.2 | The documented home of these two commands. | D |

Running a site-user command **as root** is not documented. Whether `system:permissions:reset --path=<absolute>` works for root and what it follows
(symlinks) is **unverified**; the project therefore runs these commands only as the site user, over an SSH alias of that user that the operator
configures ([SPEC.md](SPEC.md) §5.4).

## 5. What the CLI cannot do (UI-only or file-based)

These have **no** `clpctl` command. This project has no tool for them, never edits CloudPanel's database or NGINX files, and says so in the tool
descriptions instead of improvising.

| Area | How it is done | Source |
| ---- | -------------- | ------ |
| WordPress site | UI wizard | ADD, apps/wordpress |
| Listing sites, databases, certificates, cron jobs | UI only; the only list commands are `user:list` and `vhost-templates:list` | – (silence) |
| Root directory, PHP version and settings (`memory_limit`, `max_execution_time`, `max_input_time`, `max_input_vars`, `post_max_size`, `upload_max_filesize`, additional directives), Node/Python version, App Port, reverse-proxy URL, PageSpeed, site-user password and SSH keys | UI, per site | ST |
| Vhost editor (syntax check, auto-revert) | UI; or a vhost **template** by CLI (new sites only) | V |
| Per-site Basic Auth, IP and bot blocking, "Cloudflare only" | UI | FS |
| Cron jobs | UI, or `crontab -e` as the site user | `frontend-area/cron-jobs/` |
| Extra SSH/FTP users, SSH keys | UI | `frontend-area/ssh-ftp/` |
| Extra database users, database servers | UI | DB, `admin-area/settings/` |
| Varnish enable and settings | UI; `varnish-cache:purge` by CLI | VC |
| Firewall (UFW), instance reboot, services, timezone, the panel's custom domain, remote backups (rclone), events | UI | SEC, `admin-area/instance/`, `admin-area/settings/`, `admin-area/backups/` |
| Updating CloudPanel | the root script `clp-update` (plus `cloudpanel:set:release-channel`) | UP |
| Monitoring, API, webhooks | none | – |

## 6. Commands without a tool

| Command | Why |
| ------- | --- |
| `db:backup` | Not a user command: it is the nightly cron job (user `clp`). Running it by hand is a feature of the cron entry, not of the CLI. |
| `clp-update`, `clpctlWrapper`, `app:list` and any command only suggested in an error message | Not documented commands (`clp-update` is a separate root script); a tool would be a guess. |

Everything else in §2 has a tool. There is **no raw command tool**: a command the server prints in its usage listing but this project does not
know is reported by `clp_list_commands` as "not wrapped" and nothing more.

## 7. Technology stack facts the tools depend on

From page TS (read 2026-11-05; the page shows one table per operating system in tabs, so the mapping below follows the tab order and is
marked **U** until compared with a live server of each OS):

| OS | NGINX | MySQL | MariaDB | Redis | Python | Varnish |
| -- | ----- | ----- | ------- | ----- | ------ | ------- |
| Ubuntu 26.04 | 1.30 | 8.4 | 12.3, 11.8 | 8 | 3.14 | 7.7 |
| Debian 13 | 1.30 | 8.4, 8.0 | 12.3, 11.8 | 8 | 3.13 | 7.5 |
| Ubuntu 24.04 | 1.30 | 8.4, 8.0 | 10.11, 11.4, 11.8 | 7 | 3.12 | 7.5 |
| Ubuntu 22.04 | 1.21 | 8.0 | 10.6, 10.11, 11.4, 11.8 | 6 | 3.10 | 7.1 |
| Debian 12 | 1.30 | 8.4, 8.0 | 10.11, 11.4, 11.8 | 7 | 3.11 | 7.5 |

All: PHP 7.1–8.5, Node.js 12, 14, 16, 18, 20, 22, 24 (LTS, via nvm), ProFTPD 1.3, x86 and ARM64, at least 1 core, 2 GB RAM, 10 GB disk, virtual
machines only (`requirements/`, TS). Doc inconsistency noted: the installer pages still say "Ubuntu 24.04 or 22.04 or Debian 12 or 11".

Runtime versions by release (C): Node 18 → v2.2.0, 20 → v2.4.0, 22 → v2.4.2, 24 → v2.5.4; PHP 8.2 → v2.2.0, 8.3 → v2.4.0, 8.4 → v2.5.0, 8.5 → v2.5.3;
Varnish → v2.1.0; Reverse Proxy → v2.2.1.

Consequence for this project: **version values are validated by a shape pattern** (`8.4`, `22`, `3.12`), not by a list, and CloudPanel's own
refusal is reported back. A list would be stale on the day a release adds a version.

## 8. Security facts in the docs

- The panel serves HTTPS on **8443** with a self-signed certificate; after installation "bots can create the first admin" in a short window; open 8443 only
  to your own IPs, otherwise use Basic Auth (CLI) or a VPN; SSH (22) only from your IPs (`getting-started/other/`, SEC, `guides/best-practices/security/`).
- Passwords are plain option values (`--password`, `--siteUserPassword`, `--databaseUserPassword`). The docs say nothing about shell history, `ps`, `sudo`
  logging, stdin or environment input, or a password policy. **This project therefore generates passwords itself and never takes one from the model**
  (see [SPEC.md](SPEC.md) §6), but the command line still carries it (documented as a limit).
- Security fixes recur from v2.3.0 to v2.5.3, including **privilege escalation** (v2.3.0 CVE-2023-33747, v2.3.2 critical, v2.5.0 via `clpctlWrapper`, HIGH) and
  a MySQL root password leak from a site user (v2.3.2, #298). The README recommends running the current release.
- The roles are Admin (everything), Site Manager (all sites, no admin area) and User (assigned sites only) (`admin-area/users/`).

## 9. Observations

Each observation says how it was made. Observations of one server are **not** documentation: they are re-checked by the opt-in contract
test (`npm run contract-test`, maintainers only) on every CloudPanel release that the maintainers can reach.

| # | Observation | Source |
| - | ----------- | ------ |
| O1 | `clpctl` with no argument prints a usage listing of **28 commands**: the 25 of page R, `db:delete`, `cloudpanel:set:release-channel` and `system:permissions:reset`. `varnish-cache:purge` is **not** in the root listing. Plain text without a terminal, exit status 0. `list`, `help`, `--help` do not exist; the listing has no `--force` for `site:delete`. The example values differ slightly from the docs (PHP 8.3, Python 3.12, timezone `Europe/Berlin`). Fixture: `test/fixtures/recorded/usage-listing.txt`. | CloudPanel 2.5.4, a recording |
| O2 | Errors arrive as a JSON log line on stdout (`message`, `context`, `level_name`) plus a human block, non-zero exit (unknown command `list`: level CRITICAL). The exit status of a validation error was not recorded. | CloudPanel 2.5.4, a live run |
| O3 | `site:delete` asks for `yes`; `--force` skips it. | CloudPanel 2.5.4, a live run |
| O4 | `db:delete` proceeds with stdin closed and leaves the database user. A live run checked its exit status only (the site's deletion removed the database in any case); its effect is checked from the next live run on. | CloudPanel 2.5.4, a live run |
| O5 | `db:add` rejects an underscore in the database name; a hyphen is accepted. Messages on stdout. | CloudPanel 2.5.4, a live run |
| O6 | `site:add:static`, `site:add:reverse-proxy`, `site:delete`, `db:add`, `db:delete` worked as documented. | CloudPanel 2.5.4, a live run |
| O7 | `sudo -n clpctl` works without a prompt for a non-root user whose sudoers line allows `/usr/bin/clpctl` (no arguments listed, so any arguments pass). | CloudPanel 2.5.4, a live run |
| O8 | `vhost-templates:list` prints an ASCII table `Name \| Root Directory \| Type` with 27 system templates, among them versions the docs do not name (`Contao 4`, `Drupal 10`, `Laravel 12`, `Symfony 7`, `WHMCS`, `WooCommerce`, `WordPress`). Fixture: `test/fixtures/recorded/vhost-templates-list.txt`. | CloudPanel 2.5.4, a recording |
| O9 | `user:list` prints an ASCII table `User Name \| First Name \| Last Name \| E-Mail \| Role \| Status` (no timezone column). The rows were masked before being read; the fixture rows are synthetic. | CloudPanel 2.5.4, a recording |

**Never run live yet** (apart from the three read-only listings above): PHP, Node.js and Python sites, certificates (both kinds), vhost templates (add, view,
delete), the user commands that change something, `db:import`, `db:export`, Cloudflare, the release channel, `system:permissions:reset`,
`varnish-cache:purge`, `db:show:master-credentials`. The live verification of this project covers them
(see the project's `docs/LIVE-VERIFICATION.md` once it exists) and updates this table.

## 10. Open questions to settle live (none is answered by the docs)

1. (Answered by O1: the usage lines are in `test/fixtures/recorded/usage-listing.txt`.) Whether other CloudPanel versions print the same shape.
2. `clpctl` exit codes for success, validation error, "already exists", unknown command; output on stdout versus stderr.
3. Whether `db:export` / `db:import` accept an absolute `--file` as root, and where a relative file lands.
4. Whether `system:permissions:reset` works as root and what it does with symlinks.
5. Required versus optional options per command; what each rejects (site user naming rules, password rules, `--status`/`--timezone`/`--role` value sets).
6. What `vhost-template:add` does with an existing name, with a remote URL, with an invalid file.
7. What `site:delete` leaves behind (home directory, crontab, PM2 process, databases, certificate) on the current release.
8. Concurrency: two `clpctl` runs at once; and timeouts (Let's Encrypt).
