export const MAX_STREAM_CHARS = 20_000;

// Control, format (bidi marks, zero-width characters, tag characters, soft hyphen), private-use,
// unassigned, surrogate, line/paragraph separator, variation-selector and default-ignorable (Hangul fillers, combining
// grapheme joiner, ...) code points: invisible to a
// person, readable by a model. Newline, carriage return and tab are kept.
const INVISIBLE = /(?![\n\r\t])[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}\p{Variation_Selector}\p{Default_Ignorable_Code_Point}]/gu;

/** Removes ANSI escape sequences and every invisible or control character (keeps \n, \r and \t). */
export function sanitize(text: string): string {
  return text
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g, "")
    .replace(/\u001b[@-Z\\-_]/g, "")
    .replace(INVISIBLE, "");
}

/** Keeps the first `limit` characters and says how much was dropped. */
export function truncate(text: string, limit: number = MAX_STREAM_CHARS): string {
  if (text.length <= limit) return text;
  let cut = limit;
  const last = text.charCodeAt(cut - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut -= 1; // never end in the middle of a surrogate pair
  return `${text.slice(0, cut)}\n[truncated: ${text.length - cut} more characters not shown]`;
}

const SEVERE_LEVELS = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR"];

export interface ServerMessage {
  readonly message: string;
  /** The log line's level_name is ERROR or worse. */
  readonly severe: boolean;
}

/**
 * clpctl reports an error as a JSON log line on stdout (keys message, context, level_name)
 * followed by a human-readable block. Returns the `message` of that line (a severe one if there is
 * one), cleaned and bounded, or null. The text comes from the server: it is data, bounded here.
 *
 * Give it the output as the server wrote it, and `scrub` to take the secrets out of the message: the whole
 * message is scrubbed BEFORE it is cut to length (a secret cut in two would no longer be recognised), and a
 * line is found even where scrubbing the output first would have cut into its JSON.
 */
export function extractServerMessage(texts: readonly string[], scrub: (text: string) => string = (text) => text): ServerMessage | null {
  let first: ServerMessage | null = null;
  for (const text of texts) {
    for (const line of sanitize(text).split("\n")) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{") || trimmed.length > 100_000) continue;
      let data: unknown;
      try {
        data = JSON.parse(trimmed);
      } catch {
        continue;
      }
      if (typeof data !== "object" || data === null) continue;
      const { message, level_name: level } = data as { message?: unknown; level_name?: unknown };
      if (typeof message !== "string" || message.trim() === "") continue;
      const clean = sanitize(scrub(sanitize(message))).trim().slice(0, 400);
      const severe = typeof level === "string" && SEVERE_LEVELS.includes(level.toUpperCase());
      if (severe) return { message: clean, severe: true };
      first ??= { message: clean, severe: false };
    }
  }
  return first;
}

export interface Table {
  readonly headers: readonly string[];
  readonly rows: readonly (readonly string[])[];
}

const MAX_ROWS = 500;
const MAX_COLUMNS = 20;
const MAX_CELL = 200;

/**
 * The ASCII tables of `user:list` and `vhost-templates:list` (`+---+` borders, `| a | b |` rows). Give it the
 * output as the server wrote it, and `clean` to take the secrets out of each cell (before the cell is cut).
 */
export function parseTable(text: string, clean: (cell: string) => string = (cell) => cell): Table | null {
  const lines = sanitize(text)
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.startsWith("|") || l.startsWith("+"));
  const cells = (line: string): string[] =>
    line.slice(1, line.endsWith("|") ? -1 : undefined).split("|").map((c) => c.trim());
  const dataLines = lines.filter((l) => l.startsWith("|"));
  const header = dataLines[0];
  if (header === undefined) return null;
  const cell = (text: string): string => clean(text).slice(0, MAX_CELL);
  const headers = cells(header).slice(0, MAX_COLUMNS).map(cell);
  const rows = dataLines.slice(1, MAX_ROWS + 1).map((line) => cells(line).slice(0, MAX_COLUMNS).map(cell));
  return { headers, rows };
}

export interface UsageCommand {
  readonly name: string;
  readonly options: readonly string[];
}

const MAX_COMMANDS = 1000;
const MAX_OPTIONS = 100;
const USAGE_LINE = /^\s*clpctl\s+([a-z][a-z0-9:_-]{0,63})(?:\s+(.*))?$/;
const USAGE_OPTION = /--([A-Za-z][A-Za-z0-9-]{0,63})(?=[=\s\]\[,)'"]|$)/g;

/**
 * `clpctl` with no arguments prints a usage listing: group headings, `// comment` lines and one
 * ` clpctl <name> --option=value ...` example line per command (observed on CloudPanel 2.5.4).
 * Output from the server is untrusted: only well-formed command lines are kept. Empty when the
 * text has no such lines (another version, or an error).
 */
export function parseUsageListing(text: string): UsageCommand[] {
  const found = new Map<string, Set<string>>();
  for (const raw of sanitize(text).split("\n")) {
    const m = USAGE_LINE.exec(raw.trimEnd());
    const name = m?.[1];
    // every clpctl command is namespaced ("db:add"); this keeps ordinary sentences out
    if (m === null || name === undefined || !name.includes(":")) continue;
    const options = found.get(name) ?? new Set<string>();
    for (const option of (m[2] ?? "").matchAll(USAGE_OPTION)) {
      const optionName = option[1];
      if (optionName !== undefined && options.size < MAX_OPTIONS) options.add(optionName);
    }
    found.set(name, options);
    if (found.size >= MAX_COMMANDS) break;
  }
  return [...found].map(([name, options]) => ({ name, options: [...options] }));
}
