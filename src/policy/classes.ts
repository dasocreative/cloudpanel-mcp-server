/**
 * READ        always on.
 * WRITE       creates or updates, never removes. Needs allow: ["write"].
 * DESTRUCTIVE removes or overwrites data. Needs allow: ["destructive"].
 * ADMIN       changes who can get into the panel. Needs allow: ["admin"].
 * The three switches are independent: "destructive" does not imply "write".
 */
export type ToolClass = "read" | "write" | "destructive" | "admin";
export type ChangingClass = Exclude<ToolClass, "read">;

export const CHANGING_CLASSES: readonly ChangingClass[] = [
  "write",
  "destructive",
  "admin",
];

export function isChangingClass(cls: ToolClass): cls is ChangingClass {
  return cls !== "read";
}
