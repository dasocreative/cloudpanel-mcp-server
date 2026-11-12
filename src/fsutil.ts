import { chmodSync, lstatSync, mkdirSync } from "node:fs";

/**
 * Creates (if needed) a directory that only this user may use, and refuses one that is not: a symbolic
 * link, a directory owned by someone else, or one that stays open to group and others after a chmod.
 * The messages never contain the path.
 */
export function ensurePrivateDir(
  dir: string,
  /** The user that must own it; tests pass another one to see the refusal. */
  uid: number | undefined = typeof process.getuid === "function" ? process.getuid() : undefined,
): void {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (error) {
    throw new Error(`a private directory could not be created (${(error as NodeJS.ErrnoException).code ?? "error"})`);
  }
  if (process.platform === "win32") return; // no POSIX modes: the user profile's ACL applies
  let stat = lstatSync(dir);
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("a private directory is not a plain directory");
  if (uid !== undefined && stat.uid !== uid) {
    throw new Error("a private directory belongs to another user");
  }
  if ((stat.mode & 0o077) !== 0) {
    chmodSync(dir, 0o700);
    stat = lstatSync(dir);
    if ((stat.mode & 0o077) !== 0) throw new Error("a private directory is open to other users");
  }
}
