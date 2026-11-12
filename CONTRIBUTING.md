# Contributing

Thank you for helping. This project has one rule above all: **a model must never be able to do more to a server than a human has agreed to.** Changes are
judged by that first.

## Ground rules

- **Official sources first.** A fact about `clpctl` (a command, an option, a version) comes from <https://www.cloudpanel.io/docs/v2/>. What a real server showed
  is recorded with the CloudPanel release and OS. Blog posts and other projects are not sources. [docs/COMMAND-REFERENCE.md](docs/COMMAND-REFERENCE.md) is the
  record; update it with the change.
- **No raw commands.** There is no tool that runs arbitrary text, and none will be accepted.
- **No third-party code.** Do not copy code from other CloudPanel projects; write your own.
- **No personal data or secrets** in code, tests, fixtures, commit messages or examples: use `example.com`, `deploy`, `my-server`. `npm run check:hygiene` checks.
- Never read, create or commit `.env` files.

## Setup

Node 22.18 or newer (tests run the TypeScript sources directly) and bash.

```bash
npm ci
npm test
```

`npm test` builds, type-checks and runs every test (about 800, under a minute). Two tests need `openssl`; the gate and inventory tests use the system's shells.

## Adding or changing a tool

1. Define it **once** in `src/catalog/tools/*.ts`: the input schema (strict), the class, the annotations, the option types, and a `plan` that returns the exact
   command, its effects, how to undo it and what a human must type. Version values are checked by shape, not by list.
2. Add a valid example to `test/samples.ts`.
3. Add its row to the index in `docs/COMMAND-REFERENCE.md` with the source page and status (documented / observed / unverified).
4. Teach the simulator (`test/sim/clpctl.ts`) its grammar **from the documentation or a recorded output**, and keep it strict.
5. Run `npm run gen:gate` and `npm run gen:docs` and commit the results; a test fails if they drift from the catalogue.
6. Run `npm run mutation`. A guard you add should have a mutant; a survivor means the guard is not tested.

## Tests

- Unit and property tests use Node's built-in runner and `fast-check` (development only).
- Guards (validation, approval, protection, redaction, file modes) need a test that fails without them.
- Anything touching quoting is tested through real shells, and the generated gate is tested against the TypeScript validators on one corpus.
- `npm run contract-test` runs the catalogue against a real CloudPanel with throwaway names. It is for maintainers, refuses to run without explicit flags, and
  must never be pointed at a server whose sites matter.

## Releasing

Maintainers: see [docs/RELEASING.md](docs/RELEASING.md) for the settings that protect the release and the steps.

## Pull requests

Small and focused, with the checklist in the template. Explain how a change affects what a model can do. Security-relevant changes get extra scrutiny; report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is licensed under the Apache-2.0 licence of this project.
