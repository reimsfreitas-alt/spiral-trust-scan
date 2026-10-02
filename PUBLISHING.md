# Publishing checklist (owner-only steps)

Everything below needs an account, a credential or a click that only the repository owner has. Nothing here is done by the code in this repository, and nothing is hidden: if a step is not listed, it is not needed. Until these steps are done, **nothing is published**: the Action has no Marketplace listing, `@spiralcodes/trust-scanner` is not on npm, `spiral-trust` is not on PyPI, and the MCP server is not in the registry.

Naming facts, so that nothing claims more than exists:

- The GitHub owner and repository are `reimsfreitas-alt/spiral-trust-scan`. There is **no** `spiral-codes` GitHub organization; do not use `spiral-codes/...` in any link or `uses:` line.
- At the time of writing `spiral-trust` was free on PyPI and `@spiralcodes/trust-scanner` was not on the npm registry. Whether you own the npm scope `@spiralcodes` was not checked; confirm it on npmjs.com (organization or user `spiralcodes`).

## 0. Before the first release

1. Make sure the `test` workflow is green on `main` (Actions tab).
2. Decide the version. `package.json`, `python/pyproject.toml`, `python/src/spiral_trust/__init__.py` and `python/src/spiral_trust/cli.py` (`NODE_PACKAGE_VERSION`) and `mcp/server.json` (two places) must all carry the same number; a test checks it. The release tag must be `v` plus that number (for example `v0.2.0`); both publish workflows refuse a mismatch.
3. Optional smoke test of the receipt against the live service from your own machine (the build environment could not reach it, so the client was tested only against a local mock of the contract): `node bin/trust-scan.mjs test --receipt --fail-on none`, then open the printed validation URL.

## 1. GitHub Action and Marketplace

Requirements (from GitHub's docs): public repository, a single `action.yml` at the root, and a unique `name`. Docs also recommend a repository that holds only what the action needs; this repository also holds the CLI, the MCP server and the Python launcher, which is not a listed requirement but is worth knowing.

1. Check that the name `Spiral Trust Scan` is unique in the Marketplace and does not equal a user, organization or Marketplace category. If it is taken, change `name:` in `action.yml`.
2. Make sure the account that owns the repository has **two-factor authentication** enabled; publishing to the Marketplace requires it.
3. Repository > open `action.yml` > the banner **Draft a release** (or Releases > Draft a new release).
4. Tick **Publish this Action to the GitHub Marketplace**. If the box is disabled, click the link to **accept the GitHub Marketplace Developer Agreement** and accept it.
5. Pick a primary category (for example Security), set the tag (`v0.2.0`), a title, and **Publish release** (2FA prompt).

Publishing the release also triggers `release-major-tag.yml`, which moves `v1` to it so that `uses: reimsfreitas-alt/spiral-trust-scan@v1` works.

## 2. npm (`@spiralcodes/trust-scanner`)

The workflow `.github/workflows/publish-npm.yml` runs on the same release and publishes with `npm publish --provenance --access public` through npm trusted publishing (OIDC). No npm token is stored in the repository. One-time, owner-only:

1. Own or create the npm scope `@spiralcodes`.
2. On npmjs.com, open the package settings > **Trusted Publisher** > GitHub Actions, and enter: organization or user `reimsfreitas-alt`, repository `spiral-trust-scan`, workflow filename `publish-npm.yml`, no environment. Allow the direct `npm publish` action.
3. The trusted-publisher form lives on an existing package's settings page. For a name that has never been published you may therefore need one manual first publish from your machine (`npm publish --access public`, with 2FA) before step 2 is possible. This was not verifiable from the build environment; follow what npmjs.com shows.
4. Requirements the workflow already meets: npm 11.5.1 or newer, Node 22.14 or newer, a GitHub-hosted runner, `id-token: write`.

Check afterwards: the npm page shows the provenance badge and links the commit and workflow.

## 3. PyPI (`spiral-trust`)

The workflow `.github/workflows/publish-pypi.yml` builds `python/` and publishes with `pypa/gh-action-pypi-publish` using PyPI trusted publishing. No token is stored. One-time, owner-only:

1. Create or sign in to a PyPI account with 2FA.
2. Go to pypi.org > Your account > **Publishing** > add a **pending publisher** (this creates the project on first publish): project name `spiral-trust`, owner `reimsfreitas-alt`, repository `spiral-trust-scan`, workflow `publish-pypi.yml`, environment `pypi`.
3. In the GitHub repository, create an environment named `pypi` (Settings > Environments). Adding a required reviewer there gives you a final approval click before each upload.

## 4. Official MCP Registry

The registry verifies that you own the namespace and the package. Do this **after** the npm package is published, because the registry checks that the published npm package carries `mcpName` equal to the name in `server.json`.

1. Install `mcp-publisher` (release binary or Homebrew; see the registry quickstart).
2. In the `mcp/` directory run `mcp-publisher login github` and complete the device-flow sign-in **as the GitHub user `reimsfreitas-alt`**; the name `io.github.reimsfreitas-alt/spiral-trust-scanner` is only accepted for that account.
3. Run `mcp-publisher publish`.

`mcp/server.json` was checked offline against the registry's published JSON Schema (fetched from the `modelcontextprotocol/registry` repository). It has **not** been accepted by the live registry; a rejection message from `mcp-publisher publish` is the authority.

## 5. After publishing

- Awesome lists and directories: open small, factual pull requests by hand, only once the integrations above exist. Nothing in this repository submits anything anywhere.
- Add the badge to a README only if you want it; nothing inserts it automatically.
