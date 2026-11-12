import type { Profile } from "../config/types.ts";

/**
 * What an operator should know about a profile's settings. Shown by clp_server_info and by
 * `--check-config`. Each warning names the setting to change.
 */
export function profileWarnings(p: Profile): string[] {
  const out: string[] = [];
  const destructive = p.allow.has("destructive");
  if (destructive && (p.protect.siteUsers.length > 0 || p.protect.databases.length > 0)) {
    out.push(
      "clp_site_delete also removes the site user and the databases of the site it deletes, even when they are listed in protect.siteUsers or protect.databases: those lists guard the tools that take such a name; protect the DOMAIN of every site that must survive.",
    );
  }
  if (destructive && p.protect.domains.length === 0) {
    out.push("destructive tools are enabled and no domain is protected: list the sites that must never be deleted (and the panel's own domain) in protect.domains.");
  }
  if (p.allow.has("write") && p.approvalWrite === "client") {
    out.push('write tools rely on the client\'s own approval prompt (approval.write is "client"): this server asks nobody for them.');
  }
  if (p.allowUntrustedFileDirs) {
    out.push(
      "allowUntrustedFileDirs is on: the file directories may be in places other accounts can write, and root-run clpctl follows the symbolic links they plant. Use this on a throw-away test server only.",
    );
  }
  return out;
}
