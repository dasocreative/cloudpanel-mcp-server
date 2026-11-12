import type { Profile } from "../../config/types.ts";
import { isAppPort, kindPathProblem, portRangesText, type FileKind } from "../../validate/patterns.ts";
import {
  domainSchema,
  siteUserSchema,
  templateNameSchema,
} from "../../validate/schemas.ts";

export const domainName = domainSchema.describe(
  "Domain name of the site: lowercase hostname such as www.example.com (no wildcard).",
);
export const siteUser = siteUserSchema.describe(
  "Name of the site user (an SSH user that owns /home/<siteUser>): a-z, 0-9, _ and -, starting with a letter, at most 32. Choose a new one; do not reuse an existing user.",
);
export const templateName = templateNameSchema.describe(
  "Vhost template name, exactly as clp_vhost_templates_list shows it (for example Generic).",
);

/** The part of a file parameter that depends on the profile: the subdirectory and extensions of its kind. */
export function fileProblem(what: string, kind: FileKind, value: string, profile: Profile): string | null {
  const problem = kindPathProblem(kind, value, profile.fileDirs);
  return problem === null ? null : `${what} ${problem}`;
}

/** The part of an application port that depends on the profile: the ports it allows. */
export function portProblem(what: string, port: number, profile: Profile): string | null {
  return isAppPort(port, profile.appPorts)
    ? null
    : `${what} must be one of the ports this profile allows: ${portRangesText(profile.appPorts)} (profile appPorts; database, cache and admin ports are never allowed)`;
}
