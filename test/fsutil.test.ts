import assert from "node:assert/strict";
import { chmodSync, mkdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { ensurePrivateDir } from "../src/fsutil.ts";
import { IS_WINDOWS, shortTmp } from "./helpers.ts";

const mode = (path: string): number => statSync(path).mode & 0o777;

describe("ensurePrivateDir", { skip: IS_WINDOWS }, () => {
  it("creates nested directories that only the user can use, and can be called again", () => {
    const root = shortTmp();
    const dir = join(root, "a", "b", "c");
    ensurePrivateDir(dir);
    assert.equal(mode(dir), 0o700);
    ensurePrivateDir(dir);
    assert.equal(mode(dir), 0o700);
  });
  it("closes a directory that is open to group and others", () => {
    const dir = join(shortTmp(), "open");
    mkdirSync(dir, { mode: 0o755 });
    chmodSync(dir, 0o755);
    ensurePrivateDir(dir);
    assert.equal(mode(dir), 0o700);
  });
  it("refuses a symbolic link, even one that points at a directory of the same user", () => {
    const root = shortTmp();
    mkdirSync(join(root, "real"), { mode: 0o700 });
    symlinkSync(join(root, "real"), join(root, "link"));
    assert.throws(() => ensurePrivateDir(join(root, "link")), /not a plain directory/);
  });
  it("refuses a directory that belongs to someone else", () => {
    const dir = join(shortTmp(), "foreign");
    mkdirSync(dir, { mode: 0o700 });
    const me = process.getuid?.() ?? 0;
    assert.doesNotThrow(() => ensurePrivateDir(dir, me));
    assert.throws(() => ensurePrivateDir(dir, me + 1), /belongs to another user/);
    assert.throws(() => ensurePrivateDir(dir, me + 1), (error: Error) => !error.message.includes(dir));
  });
  it("refuses a regular file in the way, and never puts the path in a message", () => {
    const root = shortTmp();
    writeFileSync(join(root, "file"), "x");
    for (const target of [join(root, "file"), join(root, "file", "below")]) {
      assert.throws(() => ensurePrivateDir(target), (error: Error) => !error.message.includes(root) && /private directory/.test(error.message), target);
    }
  });
});
