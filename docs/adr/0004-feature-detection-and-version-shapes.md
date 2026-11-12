# ADR-0004: Feature detection and version values by shape

- Status: accepted (2026-11-05)

## Context

The documentation does not list required options, defaults, exit codes or a `--help`; on the observed server `clpctl list`, `help` and `--help` do not exist
and `clpctl` with no argument prints a coloured usage listing (COMMAND-REFERENCE §1). Runtime versions change with every release (Node 24 and PHP 8.5 appeared
in 2025–2026) and operating systems differ (Python 3.10 to 3.14). A hard-coded list is stale on the day a release ships.

## Decision

- Probe once per profile with `clpctl` (no arguments), parse command names and the options shown on each line, cache in memory.
- A tool is unavailable if its command is missing, or if a **required** option is not shown. Optional options are not judged by the listing (observed:
  `--force` works for `site:delete` and is not shown).
- If the listing cannot be parsed, say so and rely on `clpctl`'s own refusal; do not guess.
- Version-like values are validated by **shape** only: PHP `^[0-9]{1,2}\.[0-9]{1,2}$`, Node `^[0-9]{1,2}$`, Python `^3\.[0-9]{1,2}$`. CloudPanel decides what is installed
  and its message comes back to the model.
- Unknown commands on the server are listed, never wrapped: there is no raw command tool.

## Consequences

Works on any v2 release and OS without a release of this project. The risk is a shape that is too narrow or too wide; the live contract test and the
simulator carry the observed rules (for example the database-name rule) and the patterns for names stay strict because they reach a shell.
