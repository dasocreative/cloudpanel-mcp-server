import { fileModeSchema, purgeSchema, relativePathSchema } from "../../validate/schemas.ts";
import { annotate, defineTool, opt, req, type ToolSpec } from "../define.ts";
import { siteUser } from "./common.ts";

const SITE_USER_NOTE =
  "Runs as the SITE USER, not as root, over an SSH login that the operator configured for that user (profile siteUserAccess); without one the tool refuses and says how to run the command yourself.";

function accessProblem(user: string, profile: { siteUserAccess: Readonly<Record<string, unknown>>; name: string }): string | null {
  return !Object.hasOwn(profile.siteUserAccess, user) || profile.siteUserAccess[user] === undefined
    ? `the profile "${profile.name}" has no SSH login for the site user ${user} (siteUserAccess). Ask the operator to configure one, or run the command yourself as that user`
    : null;
}

export const siteUserTools: ToolSpec[] = [
  defineTool({
    name: "clp_system_permissions_reset",
    kind: "siteuser",
    command: "system:permissions:reset",
    cls: "write",
    title: "Reset file permissions of a site",
    summary:
      "Resets the permissions of a file or directory tree below a site user's home (clpctl system:permissions:reset, a site-user command). Typical use after uploading files: directories 770, files 660.",
    extraNote: SITE_USER_NOTE,
    shape: {
      siteUser,
      directories: fileModeSchema.optional().describe('Octal mode for directories (default "770").'),
      files: fileModeSchema.optional().describe('Octal mode for files (default "660").'),
      path: relativePathSchema.optional().describe('Relative path below the site user\'s home, for example "htdocs/www.example.com" (default "."). No ".." and no dot-directories.'),
    },
    annotations: annotate(false, false, true),
    options: {
      directories: req("fileMode"),
      files: req("fileMode"),
      path: req("relativePath"),
    },
    check: (a, p) => accessProblem(String(a["siteUser"]), p),
    plan: (a) => {
      const directories = a.directories ?? "770";
      const files = a.files ?? "660";
      const path = a.path ?? ".";
      return {
        command: "system:permissions:reset",
        options: [opt("directories", directories), opt("files", files), opt("path", path)],
        flags: [],
        summary: `Reset permissions under ~/${path === "." ? "" : path} of ${a.siteUser} (directories ${directories}, files ${files})`,
        effects: [`changes the mode of existing files and directories of the site user ${a.siteUser}`],
        undo: "set the modes again; the previous modes are not recorded",
        siteUser: a.siteUser,
        protect: [{ kind: "siteUser", value: a.siteUser }],
      };
    },
  }),
  defineTool({
    name: "clp_varnish_cache_purge",
    kind: "siteuser",
    command: "varnish-cache:purge",
    cls: "write",
    title: "Purge the Varnish cache of a site",
    summary:
      "Purges the Varnish cache (clpctl varnish-cache:purge, a site-user command): everything, some cache tags, or one URL. Varnish must be enabled for the site in the panel.",
    extraNote: SITE_USER_NOTE,
    shape: {
      siteUser,
      purge: purgeSchema.describe('"all", a comma-separated list of cache tags (at most 20), or one URL such as https://www.example.com/page.html (no port, no query).'),
    },
    annotations: annotate(false, false, true),
    options: { purge: req("purge") },
    check: (a, p) => accessProblem(String(a["siteUser"]), p),
    plan: (a) => ({
      command: "varnish-cache:purge",
      options: [opt("purge", a.purge)],
      flags: [],
      summary: `Purge the Varnish cache (${a.purge === "all" ? "everything" : a.purge}) for ${a.siteUser}`,
      effects: ["pages are rebuilt on the next request; load rises briefly"],
      undo: "not needed; the cache refills",
      siteUser: a.siteUser,
      protect: [{ kind: "siteUser", value: a.siteUser }],
    }),
  }),
];

