import { posix, win32 } from "node:path";

export const APP_DIR = "cloudpanel-mcp-server";

type Env = Readonly<Record<string, string | undefined>>;

const joiner = (platform: NodeJS.Platform) => (platform === "win32" ? win32.join : posix.join);

/** `~` and `~/x` become the home directory; anything else is returned unchanged. */
export function expandHome(path: string, home: string, platform: NodeJS.Platform = process.platform): string {
  if (path === "~") return home;
  if (path.startsWith("~/") || path.startsWith("~\\")) {
    return joiner(platform)(home, path.slice(2));
  }
  return path;
}

/** Where audit log, password files and ssh sockets live (mode 0700). */
export function defaultStateDir(
  env: Env,
  platform: NodeJS.Platform,
  home: string,
): string {
  const join = joiner(platform);
  if (platform === "win32") {
    const base = env["LOCALAPPDATA"];
    return join(base !== undefined && base !== "" ? base : join(home, "AppData", "Local"), APP_DIR);
  }
  if (platform === "darwin") {
    return join(home, "Library", "Application Support", APP_DIR);
  }
  const xdg = env["XDG_STATE_HOME"];
  return join(xdg !== undefined && xdg.startsWith("/") ? xdg : join(home, ".local", "state"), APP_DIR);
}

export function defaultConfigPath(
  env: Env,
  platform: NodeJS.Platform,
  home: string,
): string {
  const join = joiner(platform);
  if (platform === "win32") {
    const base = env["APPDATA"];
    return join(base !== undefined && base !== "" ? base : join(home, "AppData", "Roaming"), APP_DIR, "config.json");
  }
  if (platform === "darwin") {
    return join(home, "Library", "Application Support", APP_DIR, "config.json");
  }
  const xdg = env["XDG_CONFIG_HOME"];
  return join(xdg !== undefined && xdg.startsWith("/") ? xdg : join(home, ".config"), APP_DIR, "config.json");
}
