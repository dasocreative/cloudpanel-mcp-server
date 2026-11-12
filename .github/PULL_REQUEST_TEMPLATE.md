## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `npm test` passes (build, typecheck, tests)
- [ ] A new or changed tool: defined once in `src/catalog`, a sample in `test/samples.ts`, a row in `docs/COMMAND-REFERENCE.md` with its source, and `npm run gen:gate` and `npm run gen:docs` run
- [ ] A change to a guard (validation, approval, protection, redaction, modes): a test that fails without it, and `npm run mutation` still kills every mutant (or the new guard has one)
- [ ] No personal data, host names, addresses, secrets or `.env` files (`npm run check:hygiene`)
- [ ] Facts about `clpctl` come from the official documentation first; anything learned from a real server says which release and OS

## Does it change what a model can do to a server?

<!-- If yes, say how the human stays in control. -->
