import type { ToolSpec } from "./define.ts";
import { certTools } from "./tools/certs.ts";
import { databaseTools } from "./tools/databases.ts";
import { metaTools } from "./tools/meta.ts";
import { panelTools } from "./tools/panel.ts";
import { siteTools } from "./tools/sites.ts";
import { siteUserTools } from "./tools/siteuser.ts";
import { templateTools } from "./tools/templates.ts";
import { userTools } from "./tools/users.ts";

export { KNOWN_COMMANDS } from "./documented.ts";
export * from "./define.ts";

/** Every tool the project knows. Which ones a process lists depends on the profiles' settings. */
export function buildCatalog(): ToolSpec[] {
  const specs = [
    ...metaTools,
    ...siteTools,
    ...certTools,
    ...databaseTools,
    ...templateTools,
    ...userTools,
    ...panelTools,
    ...siteUserTools,
  ];
  const seen = new Set<string>();
  for (const spec of specs) {
    if (seen.has(spec.name)) throw new Error(`duplicate tool name ${spec.name}`);
    seen.add(spec.name);
  }
  return specs;
}
