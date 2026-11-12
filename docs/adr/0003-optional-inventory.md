# ADR-0003: Optional read-only inventory ("list the sites")

- Status: **accepted** (2026-11-05): included as an opt-in, unofficial companion

## Context

`clpctl` has no command that lists sites, databases or certificates (only `user:list` and `vhost-templates:list`; COMMAND-REFERENCE §5). Without a list the
model cannot answer "which sites do I have?" and protected targets cannot be checked against reality.

## Options

1. **Nothing.** The model asks the human, or the operator lists protected domains by hand. Zero extra attack surface.
2. **An optional companion script**, installed by the server's owner as root, with its own sudoers line, read-only, no arguments, clearly unofficial.
3. Read CloudPanel's private database or NGINX files from this server. **Rejected**: it couples to undocumented structure and the other gateway shows how
   brittle that is.

## Proposal (option 2)

A single POSIX shell script in `inventory/`, off by default (`inventory: true` in a profile), that prints JSON built only from
`/etc/nginx/sites-enabled/*.conf` (server names, `root /home/<user>/htdocs/<domain>/...`, `fastcgi_pass` / `proxy_pass` hints) and the certificate
paths' `notAfter` (read with `openssl x509 -noout -enddate`). It takes no arguments, writes nothing, never prints private keys or file contents beyond
those fields, and refuses to run with arguments. Tool: `clp_inventory_sites` (READ). The site type is reported as a *guess* (`php`, `proxy`, `static`);
Node/Python/proxy cannot be told apart by NGINX alone and the output says so. The README explains the `sudoers` line and how to read the script before
installing it.

## Recommendation

Include it, opt-in, in a separate directory, with its own tests and a README section that calls it unofficial. Decided on 2026-11-05.
