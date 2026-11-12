/**
 * Building the command line.
 *
 * For SSH the remote login shell parses the command, so every variable part is single-quoted
 * ("'" becomes "'\''") on top of being validated by a strict pattern, and every option is ONE token,
 * "--name=value": a value can never turn into a separate option, whatever it contains. For a local
 * run the same argv goes to execFile and no shell exists.
 */

const COMMAND_RE = /^[a-z][a-z0-9:-]{0,63}$/;
const OPTION_NAME_RE = /^[A-Za-z][A-Za-z0-9]{0,63}$/;
const FLAG_RE = /^--[a-z][a-z-]{0,31}$/;
/** The only prefixes allowed in front of the program: nothing, or `sudo -n`. */
function validPrefix(prefix: readonly string[]): boolean {
  return prefix.length === 0 || (prefix.length === 2 && prefix[0] === "sudo" && prefix[1] === "-n");
}
/** The program: an absolute path of safe characters ("/usr/bin/clpctl"). */
const PROGRAM_PATH_RE = /^\/[A-Za-z0-9._/-]{1,255}$/;

/** Always single-quote, so the shell sees one literal word. */
export function shellQuote(value: string): string {
  if (value.includes("\0")) {
    throw new Error("a NUL byte cannot be passed to a shell");
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/** "--name=value" as a single token. */
export function optionToken(name: string, value: string): string {
  if (!OPTION_NAME_RE.test(name)) {
    throw new Error("invalid option name");
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("control characters are not allowed in option values");
  }
  return `--${name}=${value}`;
}

/** A fixed, code-defined flag such as "--force". Never built from user input. */
export function flagToken(flag: string): string {
  if (!FLAG_RE.test(flag)) {
    throw new Error("invalid flag");
  }
  return flag;
}

export function assertCommandName(command: string): string {
  if (!COMMAND_RE.test(command)) {
    throw new Error("invalid clpctl command name");
  }
  return command;
}

export interface ArgvParts {
  /** e.g. ["sudo", "-n"] or [] */
  readonly prefix: readonly string[];
  /** e.g. "/usr/bin/clpctl" */
  readonly clpctlPath: string;
  /** e.g. "site:add:php"; undefined for the bare usage listing */
  readonly command?: string | undefined;
  /** "--name=value" and "--flag" tokens */
  readonly tokens: readonly string[];
}

/** The complete argv, validated. This is what a local run executes. */
export function buildArgv(parts: ArgvParts): string[] {
  const argv: string[] = [];
  if (!validPrefix(parts.prefix)) throw new Error("invalid command prefix");
  argv.push(...parts.prefix);
  if (!PROGRAM_PATH_RE.test(parts.clpctlPath) || parts.clpctlPath.includes("..")) {
    throw new Error("invalid clpctl path");
  }
  argv.push(parts.clpctlPath);
  if (parts.command !== undefined) argv.push(assertCommandName(parts.command));
  for (const token of parts.tokens) {
    if (token.includes("\0")) throw new Error("a NUL byte is not allowed");
    argv.push(token);
  }
  return argv;
}

/**
 * The single string handed to ssh. The first words (prefix, path, command) were validated against
 * a character set that needs no quoting; the tokens that follow are always quoted.
 */
export function renderRemoteCommand(parts: ArgvParts): string {
  const argv = buildArgv(parts);
  const fixed = parts.prefix.length + 1 + (parts.command === undefined ? 0 : 1);
  return argv
    .map((word, index) => (index < fixed ? word : shellQuote(word)))
    .join(" ");
}
