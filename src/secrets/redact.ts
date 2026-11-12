import { sanitize } from "../exec/output.ts";

export const REDACTED = "[REDACTED]";

/** Any option whose name contains "password" (case-insensitive) is a secret. */
export function isSecretOptionName(name: string): boolean {
  return /password/i.test(name);
}

const MAX_OPTION_NAME = 64;
const MAX_QUOTED_VALUE = 4096;
const WORD = "password";

const isNameChar = (c: string | undefined): boolean => c !== undefined && ((c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c === "-");
const isBlank = (c: string | undefined): boolean => c === " " || c === "\t";
const isSpace = (c: string): boolean => c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\v" || c === "\f";

/** Where "password" next occurs at or after `from`, comparing ASCII letters without regard to case (lower-casing the text would shift positions for some characters). */
function indexOfPassword(text: string, from: number): number {
  const last = text.length - WORD.length;
  for (let i = from; i <= last; i += 1) {
    let k = 0;
    while (k < WORD.length) {
      const code = text.charCodeAt(i + k);
      const lower = code >= 65 && code <= 90 ? code + 32 : code;
      if (lower !== WORD.charCodeAt(k)) break;
      k += 1;
    }
    if (k === WORD.length) return i;
  }
  return -1;
}

/**
 * True when `at` holds a quote (or a backslash and a quote, as a JSON-encoded line prints it) that closes
 * something around an option: the next character ends a quoted word of a command line or a JSON string.
 */
function closesAround(text: string, at: number): boolean {
  const q = text[at] === "\\" ? at + 1 : at;
  if (text[q] !== '"' && text[q] !== "'") return false;
  const next = text[q + 1];
  return next === undefined || next === "," || next === "}" || next === "]" || isSpace(next);
}

/**
 * Replaces the value of any "--*password*=value" option in a text: "--x=value", "--x value", "--x = value",
 * and a value in single or double quotes that holds spaces. It is a linear scan: a regular expression for
 * this backtracks quadratically on a long run of hyphens, and the text comes from the server.
 *
 * A value that is already the placeholder is left as it is when a closing quote, a space or the end follows
 * it: scrubbing a text a second time (the audit log does) must not eat the quote that closes the word, and a
 * JSON line whose password was already replaced must stay JSON.
 */
export function scrubPasswordOptions(text: string): string {
  let out = "";
  let copied = 0;
  let from = 0;
  for (;;) {
    const at = indexOfPassword(text, from);
    if (at < 0) break;
    from = at + 1;
    // the option name runs left of "password" over letters and hyphens and must contain "--"
    let start = at;
    let steps = 0;
    while (start > 0 && isNameChar(text[start - 1]) && steps < MAX_OPTION_NAME) {
      start -= 1;
      steps += 1;
    }
    if (text.slice(start, at).indexOf("--") < 0) continue;
    let end = at + WORD.length;
    steps = 0;
    while (end < text.length && isNameChar(text[end]) && steps < MAX_OPTION_NAME) {
      end += 1;
      steps += 1;
    }
    // then "=value", "= value" or " value" (blanks only: the next line is not a value)
    let p = end;
    while (isBlank(text[p])) p += 1;
    const blanks = p > end;
    const equals = text[p] === "=";
    if (equals) {
      p += 1;
      while (isBlank(text[p])) p += 1;
    } else if (!blanks) {
      continue;
    }
    let valueStart = p;
    // "--password |" is a cell of a table (a name that ends in "--password"), not an option and its value
    if (!equals && text[p] === "|" && (p + 1 >= text.length || isSpace(text[p + 1] as string))) continue;
    if (text.startsWith(REDACTED, valueStart)) {
      const after = valueStart + REDACTED.length;
      if (after >= text.length || isSpace(text[after] as string) || closesAround(text, after)) continue;
    }
    let valueEnd: number;
    let quote = text[valueStart];
    let opener = 1;
    if (quote === "\\" && (text[valueStart + 1] === '"' || text[valueStart + 1] === "'")) {
      // a quote escaped by a backslash, as a log line that was itself quoted or JSON-encoded prints it
      quote = text[valueStart + 1];
      opener = 2;
    }
    if (quote === '"' || quote === "'") {
      let close = -1;
      for (let i = valueStart + opener; i < text.length && i <= valueStart + MAX_QUOTED_VALUE; i += 1) {
        if (text[i] === quote) {
          close = i;
          break;
        }
      }
      valueStart += opener;
      if (close >= valueStart) {
        // an escaped closing quote: its backslash is not part of the value either
        valueEnd = opener === 2 && close > valueStart && text[close - 1] === "\\" ? close - 1 : close;
      } else {
        // a quote that never closes: the value probably holds spaces, so take the rest of the line
        valueEnd = valueStart;
        while (valueEnd < text.length && text[valueEnd] !== "\n" && valueEnd - valueStart < MAX_QUOTED_VALUE) valueEnd += 1;
      }
    } else {
      // up to the next space: a quote inside the value does not end it
      valueEnd = valueStart;
      while (valueEnd < text.length && !isSpace(text[valueEnd] as string)) valueEnd += 1;
    }
    if (valueEnd === valueStart) continue;
    out += text.slice(copied, valueStart) + REDACTED;
    copied = valueEnd;
    from = Math.max(from, valueEnd);
  }
  return out + text.slice(copied);
}

/**
 * Remembers every password this process generated and removes them, and any "--*password*=value",
 * from every text that leaves the process (tool results, audit log, errors).
 */
export class Redactor {
  private readonly secrets = new Set<string>();

  add(secret: string): void {
    if (secret.length >= 8) this.secrets.add(secret);
  }

  has(value: string): boolean {
    return this.secrets.has(value);
  }

  /**
   * Escape sequences and invisible characters are removed FIRST: a secret with a zero-width character or a
   * colour code inside would otherwise survive the search and be put back together by the cleaning that
   * follows.
   */
  scrub(text: string): string {
    let out = sanitize(text);
    for (const secret of this.secrets) out = out.split(secret).join(REDACTED);
    return scrubPasswordOptions(out);
  }

  /** One "--name=value" token for display: secrets become [REDACTED]. */
  displayToken(token: string): string {
    const m = /^--([A-Za-z0-9]+)=([\s\S]*)$/.exec(token);
    if (m !== null) {
      const name = m[1] ?? "";
      const value = m[2] ?? "";
      if (isSecretOptionName(name) || this.has(value)) return `--${name}=${REDACTED}`;
    }
    return this.scrub(token);
  }
}
