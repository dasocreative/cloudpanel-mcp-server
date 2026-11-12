# Releasing (for maintainers)

The release workflow ([.github/workflows/release.yml](../.github/workflows/release.yml)) is **inactive** until you set it up. Its `if` on the default branch is a convenience,
not a protection: GitHub reads the workflow file of the branch that is dispatched, so anyone who can push a branch can run a copy without it. What protects the
npm token is the repository's settings, so set them first.

## Settings that make the release safe

1. **Environment `npm-publish`** (Settings, Environments): required reviewers (not the person who starts the run) and *Prevent self-review*; **Deployment branches and tags:
   selected, `main` only**.
2. **The npm token is an *environment* secret of `npm-publish`**, never a repository secret (a repository secret is readable by any workflow on any branch). Use a granular
   token that can publish only this package and expires. Better: **npm trusted publishing** (npmjs.com, package settings, trusted publisher: this repository, the workflow
   `release.yml`, the environment `npm-publish`); then no token exists, and the `NPM_TOKEN` line of the publish step can be removed.
3. **Branch protection on `main`**: pull request with review, required status checks (the CI jobs), no force-push, no deletion; protect release tags.
4. **Workflow files need review**: a CODEOWNERS entry for `.github/workflows/` and `scripts/`; *Require approval for all outside collaborators*; the default workflow
   token read-only (Settings, Actions, General).
5. Repository variable `RELEASE_ENABLED` = `true` only when you mean to release.

## Steps

1. A clean `main`: CI green, `CHANGELOG.md` has the version, `package.json` has the version and **no** `"private": true`.
2. `npm test`, `npm run mutation`, `node scripts/check-hygiene.mjs --history-content --patterns-file <yours>`, `node scripts/check-pack.mjs`, `npm audit --omit=dev`.
3. Run the workflow (*Release*, input: the version). `verify` runs everything again, `build` packs one tarball and records its checksum, a reviewer approves, `publish`
   checks the tarball (checksum, file list, no install-time script, the two dependencies at exact versions, `bin`, version) and publishes exactly that file with provenance.
4. Check the package page for the provenance badge, install it once in a clean directory, run `--check-config`.

What the workflow cannot do: the compiler runs in the build job, so a compromised compiler could produce a malicious `dist/`; the checksum and the publish-time checks catch
tampering after the build, not before it. Pin and review dependency updates (Dependabot, dependency review) accordingly.

## First release (0.1.0): the checklist

The repository side is ready: `package.json` is no longer private and names the repository (npm provenance needs it), the CHANGELOG has 0.1.0, and the
package holds only the files `npm run check:pack` allows. What is left needs the maintainer's own accounts:

1. **npm.** An npmjs.com account with two-factor authentication. Then either
   - **trusted publishing** (preferred, no token at all): on npmjs.com, the package's settings, *Trusted publisher*: GitHub Actions, this repository, workflow
     `release.yml`, environment `npm-publish`; or
   - if npm does not offer that for a package that does not exist yet: a **granular access token** that can publish only `cloudpanel-mcp-server` and expires
     within days, saved as the environment secret `NPM_TOKEN` of `npm-publish` (step 2). After the first release switch to trusted publishing and delete it.
2. **GitHub settings** (Settings, or with `gh`; `OWNER/REPO` is this repository):
   ```bash
   gh api -X PUT repos/OWNER/REPO/private-vulnerability-reporting          # SECURITY.md sends reports there
   gh api -X PUT repos/OWNER/REPO/environments/npm-publish                  # then, in Settings, Environments: reviewers and "main" only
   gh secret set NPM_TOKEN --env npm-publish --repo OWNER/REPO              # only with a token (step 1)
   gh variable set RELEASE_ENABLED --body true --repo OWNER/REPO
   ```
   Add branch protection on `main` (Settings, Branches). A maintainer working alone is the environment's only reviewer: leave *Prevent self-review* off,
   or the release can never be approved.
3. **Release:** CI green on `main`, then `gh workflow run release.yml -f version=0.1.0 --repo OWNER/REPO`, approve the `publish` job, and check
   <https://www.npmjs.com/package/cloudpanel-mcp-server> for the provenance badge. Then `npx -y cloudpanel-mcp-server@0.1.0 --version` in a clean directory.
4. **Tag and notes:** `git tag v0.1.0 && git push origin v0.1.0`, and a GitHub release from the CHANGELOG section. Set `RELEASE_ENABLED` back to `false`.
