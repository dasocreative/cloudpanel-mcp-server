#!/bin/bash
# cloudpanel-mcp-setup.sh - prepares a CloudPanel v2 server for cloudpanel-mcp-server, in one run.
#
# Run it ONCE, as root, on the CloudPanel server. It is easiest to send it from your own machine:
#
#   npx -y cloudpanel-mcp-server@<version> --print-server-setup \
#     | ssh root@<server> "bash -s -- --key '$(cat ~/.ssh/id_ed25519_cloudpanel.pub)'"
#
# (read it first with: npx -y cloudpanel-mcp-server@<version> --print-server-setup | less)
#
# What it does, and nothing else:
#   1. creates a dedicated account (default: cloudpanel-mcp) with no password, or reuses an existing one;
#   2. allows that account exactly one program as root, clpctl (/etc/sudoers.d/cloudpanel-mcp-server, checked by visudo);
#   3. creates the root-owned directories for database dumps, certificates and vhost templates
#      (/var/lib/cloudpanel-mcp-server/{dumps,certs,templates});
#   4. installs the gate (/usr/local/sbin/cloudpanel-mcp-gate.sh): the key can then run ONLY the clpctl commands the
#      MCP server has tools for, with checked values, and never a shell. Destructive and admin commands are refused
#      unless you pass --allow all;
#   5. pins your public key to the gate in the account's authorized_keys (root-owned when the account is new, so the
#      account cannot add keys of its own);
#   6. optionally (--inventory) installs the read-only "list the sites" helper;
#   7. tests the whole chain as the new account and prints what to put in your MCP client.
#
# It changes no CloudPanel setting, no site, no firewall and no SSH server setting. Running it again is safe.
# Undo: docs/SETUP.md, "Remove it from a server".

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: cloudpanel-mcp-setup.sh --key '<public key>' [options]

  --key '<line>'      the PUBLIC key (one line of a .pub file) the MCP server will log in with (required, unless --no-key)
  --no-key            do not touch authorized_keys (you will add the key yourself)
  --user <name>       the account to create or reuse (default: cloudpanel-mcp)
  --allow <level>     what the key may ever do on this server, whatever the MCP client asks:
                        read   only look (no change at all)
                        write  look, add and update: sites, databases, certificates, templates (default)
                        all    also delete and administer panel users (each call still needs your typed approval)
  --no-gate           pin the key without the gate (NOT recommended: the key can then run any clpctl command)
  --inventory         also install the read-only "list the sites" helper
  --dry-run           print what would be done, change nothing
  --help              this text
EOF
}

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'cloudpanel-mcp-setup: %s\n' "$*" >&2; exit 1; }

# The gate and the inventory helper. `cloudpanel-mcp-server --print-server-setup` replaces the two functions between
# the markers with the files of the same release; run from a checkout, the files next to this script are used.
# @@EMBEDDED-START
embedded_gate() { return 1; }
embedded_inventory() { return 1; }
# @@EMBEDDED-END

main() {
  exec </dev/null # nothing below may read the rest of a script that arrives on stdin
  umask 022

  local user=cloudpanel-mcp key="" no_key=0 allow=write use_gate=1 inventory=0 dry=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --key) [ $# -ge 2 ] || die "--key needs a value"; key=$2; shift 2 ;;
      --key=*) key=${1#--key=}; shift ;;
      --no-key) no_key=1; shift ;;
      --user) [ $# -ge 2 ] || die "--user needs a value"; user=$2; shift 2 ;;
      --user=*) user=${1#--user=}; shift ;;
      --allow) [ $# -ge 2 ] || die "--allow needs a value"; allow=$2; shift 2 ;;
      --allow=*) allow=${1#--allow=}; shift ;;
      --no-gate) use_gate=0; shift ;;
      --inventory) inventory=1; shift ;;
      --dry-run) dry=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done

  # ---------------------------------------------------------------- checks (nothing is changed before they all pass)
  step "Checks"
  [ "$(id -u)" -eq 0 ] || die "run it as root (for example: ssh root@<server> 'bash -s' or sudo bash cloudpanel-mcp-setup.sh)"
  local clpctl
  clpctl=$(command -v clpctl 2>/dev/null || true)
  [ -n "$clpctl" ] || { [ -x /usr/bin/clpctl ] && clpctl=/usr/bin/clpctl; } || true
  [ -n "$clpctl" ] && [ -x "$clpctl" ] || die "clpctl not found: this does not look like a CloudPanel v2 server"
  case "$clpctl" in /*) ;; *) die "clpctl is not an absolute path: $clpctl" ;; esac
  command -v sudo >/dev/null 2>&1 || die "sudo is not installed (apt-get install sudo)"
  command -v visudo >/dev/null 2>&1 || die "visudo is not installed (it comes with sudo)"
  [ -d /etc/sudoers.d ] || die "/etc/sudoers.d does not exist"
  grep -Eq '^[[:space:]]*[@#]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers 2>/dev/null \
    || die "/etc/sudoers does not include /etc/sudoers.d (add: @includedir /etc/sudoers.d)"

  printf '%s' "$user" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "--user: use 1-32 lower-case letters, digits, _ or -"
  case "$user" in root | clp | mysql | nobody | www-data | daemon | bin | sys) die "--user: '$user' is a system account" ;; esac
  case "$allow" in read | write | all) ;; *) die "--allow must be read, write or all" ;; esac

  local exists=0 home=""
  if getent passwd "$user" >/dev/null; then
    exists=1
    home=$(getent passwd "$user" | cut -d: -f6)
    [ "$(id -u "$user")" -ge 1000 ] || die "--user: '$user' is a system account (uid below 1000)"
    [ ! -d "$home/htdocs" ] || die "--user: '$user' is a CloudPanel site user (it has $home/htdocs); choose another name"
    say "account $user exists: it is reused (its password and other keys are left as they are)"
  else
    home=/home/$user
    say "account $user will be created (no password: key login only)"
  fi

  if [ "$no_key" -eq 0 ]; then
    [ -n "$key" ] || die "--key '<public key>' is required (or --no-key). Example: --key \"\$(cat ~/.ssh/id_ed25519_cloudpanel.pub)\""
    printf '%s' "$key" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}( [A-Za-z0-9@._+-]{0,100})?$' \
      || die "--key must be ONE public key line, e.g. 'ssh-ed25519 AAAA... name' (the .pub file, never the private key)"
  fi

  local gate_text="" inventory_text="" here
  here=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)
  if [ "$use_gate" -eq 1 ]; then
    if gate_text=$(embedded_gate); then :
    elif [ -f "$here/cloudpanel-mcp-gate.sh" ]; then gate_text=$(cat "$here/cloudpanel-mcp-gate.sh")
    else die "the gate is not embedded and not next to this script: use --print-server-setup, or run it from hardening/ of a checkout"
    fi
    case "${gate_text:0:200}" in *cloudpanel-mcp-gate.sh*) ;; *) die "the gate looks wrong; get the script again" ;; esac
  fi
  if [ "$inventory" -eq 1 ]; then
    if inventory_text=$(embedded_inventory); then :
    elif [ -f "$here/../inventory/cloudpanel-mcp-inventory" ]; then inventory_text=$(cat "$here/../inventory/cloudpanel-mcp-inventory")
    else die "the inventory helper is not embedded and not in ../inventory/: use --print-server-setup"
    fi
  fi
  say "clpctl: $clpctl; level: $allow; gate: $([ "$use_gate" -eq 1 ] && echo yes || echo NO); inventory: $([ "$inventory" -eq 1 ] && echo yes || echo no)"

  if [ "$dry" -eq 1 ]; then
    step "Dry run: nothing was changed. Without --dry-run this would:"
    [ "$exists" -eq 1 ] || say "  useradd --create-home --shell /bin/bash --user-group $user"
    say "  write /etc/sudoers.d/cloudpanel-mcp-server: $user ALL=(root) NOPASSWD: $clpctl"
    [ "$inventory" -eq 0 ] || say "    and: $user ALL=(root) NOPASSWD: /usr/local/sbin/cloudpanel-mcp-inventory \"\""
    say "  create /var/lib/cloudpanel-mcp-server/{dumps,certs,templates} (root-owned)"
    [ "$use_gate" -eq 0 ] || say "  install /usr/local/sbin/cloudpanel-mcp-gate.sh (level $allow)"
    [ "$inventory" -eq 0 ] || say "  install /usr/local/sbin/cloudpanel-mcp-inventory"
    [ "$no_key" -eq 1 ] || say "  add the key to $home/.ssh/authorized_keys$([ "$use_gate" -eq 1 ] && echo ', pinned to the gate')"
    exit 0
  fi

  # ---------------------------------------------------------------- 1. account
  step "1. Account"
  if [ "$exists" -eq 0 ]; then
    useradd --create-home --shell /bin/bash --user-group "$user"
    home=$(getent passwd "$user" | cut -d: -f6)
    say "created $user (password locked: only an SSH key can log in)"
  else
    say "reusing $user"
  fi

  # ---------------------------------------------------------------- 2. sudoers
  step "2. sudo: exactly one program as root"
  local tmp
  tmp=$(mktemp)
  {
    say "# cloudpanel-mcp-server: the account may run clpctl as root, nothing else"
    say "$user ALL=(root) NOPASSWD: $clpctl"
    [ "$inventory" -eq 0 ] || say "$user ALL=(root) NOPASSWD: /usr/local/sbin/cloudpanel-mcp-inventory \"\""
  } >"$tmp"
  visudo -cqf "$tmp" || { rm -f "$tmp"; die "visudo refused the sudoers line; nothing was installed"; }
  install -o root -g root -m 0440 "$tmp" /etc/sudoers.d/cloudpanel-mcp-server
  rm -f "$tmp"
  visudo -cq || die "visudo reports an error in the sudo configuration: check /etc/sudoers.d/cloudpanel-mcp-server"
  say "/etc/sudoers.d/cloudpanel-mcp-server"

  # ---------------------------------------------------------------- 3. directories
  step "3. Directories for dumps, certificates and templates (root-owned)"
  install -d -m 0755 -o root -g root /var/lib/cloudpanel-mcp-server
  install -d -m 0700 -o root -g root /var/lib/cloudpanel-mcp-server/dumps /var/lib/cloudpanel-mcp-server/certs
  install -d -m 0755 -o root -g root /var/lib/cloudpanel-mcp-server/templates
  say "/var/lib/cloudpanel-mcp-server/{dumps,certs,templates}"

  # ---------------------------------------------------------------- 4. gate and inventory
  if [ "$use_gate" -eq 1 ]; then
    step "4. Gate (level: $allow)"
    local w=1 d=0 a=0 inv=0
    case "$allow" in read) w=0 ;; all) d=1; a=1 ;; esac
    [ "$inventory" -eq 0 ] || inv=1
    tmp=$(mktemp)
    printf '%s\n' "$gate_text" | sed \
      -e "s|^ALLOW_WRITE=[01]|ALLOW_WRITE=$w|" \
      -e "s|^ALLOW_DESTRUCTIVE=[01]|ALLOW_DESTRUCTIVE=$d|" \
      -e "s|^ALLOW_ADMIN=[01]|ALLOW_ADMIN=$a|" \
      -e "s|^ALLOW_INVENTORY=[01]|ALLOW_INVENTORY=$inv|" \
      -e "s|^CLPCTL=/.*|CLPCTL=$clpctl|" >"$tmp"
    grep -q "^ALLOW_WRITE=$w" "$tmp" && grep -q "^ALLOW_DESTRUCTIVE=$d" "$tmp" && grep -q "^ALLOW_ADMIN=$a" "$tmp" \
      && grep -q "^CLPCTL=$clpctl\$" "$tmp" || { rm -f "$tmp"; die "could not set the gate's settings; nothing more was changed"; }
    bash -n "$tmp" || { rm -f "$tmp"; die "the gate does not parse; nothing more was changed"; }
    install -o root -g root -m 0755 "$tmp" /usr/local/sbin/cloudpanel-mcp-gate.sh
    rm -f "$tmp"
    say "/usr/local/sbin/cloudpanel-mcp-gate.sh (to protect sites from changes, list them in PROTECT_DOMAINS there)"
  fi
  if [ "$inventory" -eq 1 ]; then
    tmp=$(mktemp)
    printf '%s\n' "$inventory_text" >"$tmp"
    sh -n "$tmp" || { rm -f "$tmp"; die "the inventory helper does not parse"; }
    install -o root -g root -m 0755 "$tmp" /usr/local/sbin/cloudpanel-mcp-inventory
    rm -f "$tmp"
    say "/usr/local/sbin/cloudpanel-mcp-inventory"
  fi

  # ---------------------------------------------------------------- 5. key
  if [ "$no_key" -eq 0 ]; then
    step "5. Key"
    local line="restrict $key"
    [ "$use_gate" -eq 0 ] || line="command=\"/usr/local/sbin/cloudpanel-mcp-gate.sh\",restrict $key"
    local keybody ak="$home/.ssh/authorized_keys"
    keybody=$(printf '%s' "$key" | awk '{print $2}')
    if [ ! -d "$home/.ssh" ]; then
      if [ "$exists" -eq 0 ]; then
        # a new account: root owns its .ssh, so the account can never add or swap a key that skips the gate
        install -d -o root -g root -m 0755 "$home/.ssh"
      else
        install -d -o "$user" -g "$(id -gn "$user")" -m 0700 "$home/.ssh"
      fi
    fi
    # an existing .ssh keeps its owner and mode (on a re-run of this script: root, 0755)
    if [ ! -e "$ak" ]; then
      if [ "$(stat -c %U "$home/.ssh")" = root ]; then
        install -o root -g root -m 0644 /dev/null "$ak"
      else
        install -o "$user" -g "$(id -gn "$user")" -m 0600 /dev/null "$ak"
      fi
    fi
    # replace a line with the same key, keep every other line; the file keeps its owner and mode
    tmp=$(mktemp)
    grep -vF "$keybody" "$ak" >"$tmp" || true
    printf '%s\n' "$line" >>"$tmp"
    cat "$tmp" >"$ak"
    rm -f "$tmp"
    if [ "$(stat -c %U "$home/.ssh")" != root ]; then
      say "note: $user can edit its own authorized_keys (its .ssh is not root-owned): a dedicated account made by this script is safer"
    fi
    say "$home/.ssh/authorized_keys$([ "$use_gate" -eq 1 ] && echo ': key pinned to the gate' || echo ': key WITHOUT the gate')"
  fi

  # ---------------------------------------------------------------- 6. SSH server settings that would refuse the account
  step "6. SSH server"
  local sshd_t=""
  sshd_t=$( (sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) || true)
  if [ -n "$sshd_t" ]; then
    local allowusers allowgroups
    allowusers=$(printf '%s\n' "$sshd_t" | awk '$1=="allowusers"{print $2}' | tr '\n' ' ')
    allowgroups=$(printf '%s\n' "$sshd_t" | awk '$1=="allowgroups"{print $2}' | tr '\n' ' ')
    if [ -n "$allowusers" ] && ! printf ' %s ' "$allowusers" | grep -q " $user "; then
      say "WARNING: sshd only lets in: $allowusers"
      say "         add $user to the AllowUsers line of your sshd configuration, then: sshd -t && systemctl reload ssh"
    elif [ -n "$allowgroups" ]; then
      say "WARNING: sshd has AllowGroups ($allowgroups): make sure $user is in one of them"
    elif printf '%s\n' "$sshd_t" | awk '$1=="denyusers"{print $2}' | grep -qx "$user"; then
      say "WARNING: sshd's DenyUsers names $user"
    else
      say "sshd lets $user in (key login)"
    fi
    printf '%s\n' "$sshd_t" | grep -qx 'pubkeyauthentication no' && say "WARNING: sshd has PubkeyAuthentication no"
  else
    say "could not read the sshd settings (sshd -T); skipped"
  fi

  # ---------------------------------------------------------------- 7. test as the account
  step "7. Test: the account runs clpctl through sudo$([ "$use_gate" -eq 1 ] && echo ' and the gate')"
  local out rc=0
  if [ "$use_gate" -eq 1 ]; then
    out=$(su -s /bin/bash -c "SSH_ORIGINAL_COMMAND='sudo -n $clpctl' /usr/local/sbin/cloudpanel-mcp-gate.sh" "$user" 2>&1) || rc=$?
  else
    out=$(su -s /bin/bash -c "sudo -n $clpctl" "$user" 2>&1) || rc=$?
  fi
  if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'clpctl'; then
    say "ok: clpctl answered ($(printf '%s\n' "$out" | grep -c ' clpctl ' || true) commands listed)"
  else
    say "FAILED (exit $rc). Output:"
    printf '%s\n' "$out" | sed -n '1,15p'
    die "the test failed: see the output above"
  fi

  # ---------------------------------------------------------------- done
  local next="npx -y cloudpanel-mcp-server@<version> --init --host <this server's address>"
  [ "$user" = cloudpanel-mcp ] || next="$next --user $user"
  case "$allow" in
    write) next="$next --allow write" ;;
    all) next="$next --allow write,destructive,admin" ;;
  esac
  step "Done. Now, on YOUR machine (it writes the client configuration and checks the connection):"
  say "  $next"
  say "  (add --identity-file <private key> if it is not ~/.ssh/id_ed25519_cloudpanel; leave out --allow to start read-only)"
}

main "$@"
