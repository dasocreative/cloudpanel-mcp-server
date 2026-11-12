import type { Profile } from "../config/types.ts";

export type ProtectKind = "domain" | "siteUser" | "database" | "panelUser";

export interface ProtectCheck {
  readonly kind: ProtectKind;
  readonly value: string;
}

/**
 * CloudPanel treats www.example.com and example.com as one site, so protection ignores a leading "www.".
 * It ignores every leading "www.": a site called www.www.example.com would claim www.example.com as its
 * "other form", the protected site's own host name.
 */
function bare(domain: string): string {
  let d = domain;
  while (d.startsWith("www.")) d = d.slice(4);
  return d;
}

function domainProtected(list: readonly string[], domain: string): boolean {
  const d = bare(domain);
  return list.some((entry) => {
    if (entry.startsWith("*.")) {
      const suffix = bare(entry.slice(2));
      // a wildcard also covers the apex: failing closed is the safer reading
      return d === suffix || d.endsWith(`.${suffix}`);
    }
    return bare(entry) === d;
  });
}

/** Names are matched without regard to case: CloudPanel or MySQL may fold case, and failing closed costs nothing. */
function inList(list: readonly string[], value: string): boolean {
  const v = value.toLowerCase();
  return list.some((entry) => entry.toLowerCase() === v);
}

/** The reason a target is protected in this profile, or null. */
export function protectedReason(profile: Profile, check: ProtectCheck): string | null {
  const p = profile.protect;
  switch (check.kind) {
    case "domain":
      return domainProtected(p.domains, check.value)
        ? `the domain ${check.value} is protected in profile "${profile.name}" (protect.domains): it cannot be changed through this server`
        : null;
    case "siteUser":
      return inList(p.siteUsers, check.value)
        ? `the site user ${check.value} is protected in profile "${profile.name}"`
        : null;
    case "database":
      return inList(p.databases, check.value)
        ? `the database ${check.value} is protected in profile "${profile.name}"`
        : null;
    case "panelUser":
      return inList(p.panelUsers, check.value)
        ? `the panel user ${check.value} is protected in profile "${profile.name}"`
        : null;
  }
}
