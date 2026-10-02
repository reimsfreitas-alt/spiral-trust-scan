# Spiral Trust Scan

A local, offline scan of agent code or tool logs. It looks for five things a reviewer would ask about an AI agent that can act in the world:

1. **Authorization gap**: tool calls with external effects and no visible authorization or policy gate.
2. **Unverifiable effect**: external effects with no visible receipt, ledger or independent observation.
3. **Replay risk**: external effects with no visible idempotency or deduplication.
4. **Irreversible action without confirmation**: delete, refund, transfer, charge, publish or send with no visible confirmation or dry run.
5. **Secrets and untrusted instructions** in the scanned material.

It ships as a CLI, a GitHub Action, an npm package, a thin PyPI launcher and an MCP server. All of them run the same scan.

## What it is, and what it is not

It is a **heuristic over text**. It searches for signals; it does not run your code and it proves nothing. A missing signal is not proof of a gap (your gate may live in a file that was not scanned or use a word the patterns do not know), and a present signal is not proof of safety. Treat findings as questions to answer, not verdicts.

The scan runs entirely on your machine. The scan code has no network code, and a test in the repository fails if that ever changes. The single exception is the **opt-in** receipt step (`--receipt`, Action input `receipt: true`), which lives in one separate file, `src/receipt-client.mjs`, is loaded only when you ask for it, and sends two digests and counts, never your code (see [Receipts and badge](#receipts-and-badge)).

## CLI

```
npx @spiralcodes/trust-scanner path/to/agent --fail-on high
# or, from a clone of this repository:
node bin/trust-scan.mjs path/to/agent --fail-on high
```

| Option | Meaning |
| --- | --- |
| `--mode quick\|deep` | `quick` (default): one scan window of 120,000 characters, the same ceiling the free web scanner applies; files are read in sorted order until the next one does not fit. `deep`: up to 10 such windows (1,200,000 characters). Each window is analysed exactly as `quick` would analyse it and findings are merged by id. |
| `--format text\|json\|markdown\|sarif` | Output format on stdout (default `text`). |
| `--fail-on critical\|high\|medium\|none` | Threshold for exit code 1 (default `high`). |
| `--sarif-file path` | Also write SARIF 2.1.0 to a file. |
| `--receipt` | Opt-in. Submit two digests and counts and print the validation link. See below. |
| `--include-source` | With `--receipt`: also send `GITHUB_REPOSITORY` and `GITHUB_SHA`. Off by default. |
| `--label name` | Label for the report. |
| `--` | End of options. |

Exit code 0 is below the threshold, 1 is at or above it, 2 is a usage error.

**What `deep` is, and is not.** `deep` reads more files; it is not a smarter analysis. Checks about something missing (no gate, no receipt, no idempotency key) are evaluated per window, so on the same code `deep` can report more of them than `quick` when a gate lives in a file that landed in another window. Use it to widen coverage, and read the extra findings with that in mind. The output says how many files were not scanned.

**Limits.** Files up to 200 KB with common source and log extensions; `node_modules`, `.git` and build folders are skipped.

**Hashes.** `--format json` includes `meta.target_hash` and `meta.findings_hash`, so anyone can recompute them from the same files:

- `target_hash`: sha256 over the scanned files sorted by relative path (POSIX separators, relative to the scan root); for each file, the bytes `path`, NUL, byte length, NUL, file bytes, newline. Only files inside the scan window are included.
- `findings_hash`: sha256 of the canonical JSON (sorted keys, no whitespace) of the findings array ordered by finding id.

## GitHub Action

```yaml
- uses: reimsfreitas-alt/spiral-trust-scan@v1
  with:
    path: .
    mode: quick        # quick | deep
    fail-on: high      # critical | high | medium | none
    receipt: false     # true | false (opt-in)
```

`@v1` exists once the owner has published the first release (see `PUBLISHING.md`); until then use `@main`. The repository owner is `reimsfreitas-alt`; there is no `spiral-codes` organization.

**Inputs**

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Path to scan, relative to the workspace. |
| `mode` | `quick` | `quick` or `deep`, as defined in [CLI](#cli). |
| `fail-on` | `high` | Fail the job at this severity or above (`critical`, `high`, `medium`, `none`). |
| `receipt` | `false` | `true` submits two digests and counts for a receipt. Best-effort: a network failure never changes the scan result or the exit code. |
| `include-source` | `false` | With `receipt: true`, also send the repository name and commit SHA. |
| `sarif-file` | empty | Also write a SARIF 2.1.0 file at this path. |

**Outputs**

| Output | Meaning |
| --- | --- |
| `findings` | Total number of findings. |
| `counts-json` | Counts by severity, for example `{"critical":0,"high":1,"medium":2,"low":0}`. |
| `receipt_id` | Receipt id; empty unless a receipt was created. |
| `validation_url` | Public validation link; empty unless a receipt was created. |
| `sarif-file` | Path of the SARIF file written; empty if none. |

There is deliberately no numeric `score` output. The scan counts heuristic signals by severity; turning that into one number would suggest a precision it does not have.

**Job Summary.** Every run writes a Markdown summary to `$GITHUB_STEP_SUMMARY`: a findings table by severity, the findings, the plain statement that the scan is a heuristic and not proof, and, with `receipt: true`, the validation link and the badge Markdown. Outputs are written before the step exits, so they are available even when the threshold fails the job (use `if: always()` in later steps).

**SARIF upload to code scanning.**

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - id: scan
    uses: reimsfreitas-alt/spiral-trust-scan@v1
    with:
      sarif-file: trust-scan.sarif
  - if: always() && steps.scan.outputs.sarif-file != ''
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: trust-scan.sarif
```

SARIF results need a file and a line. Most findings are about something missing, so the location is the first place the triggering signal appears (for example the first external effect), and each message says so. Code-scanning availability for private repositories depends on your GitHub plan, and fork pull requests cannot write security events.

## npm

```
npm install --global @spiralcodes/trust-scanner     # bins: trust-scan, trust-scanner, spiral-trust-scanner
npx @spiralcodes/trust-scanner ./agent
```

The package has no runtime dependencies and needs Node 18 or newer. Releases are published from GitHub Actions with npm provenance, so the npm page links the package to the source commit and workflow. The package is not on npm until the owner publishes the first release (see `PUBLISHING.md`).

## PyPI

```
pip install spiral-trust
spiral-trust ./agent --fail-on high
```

`spiral-trust` is a thin launcher, not a Python re-implementation. It finds Node and runs this CLI (`npx @spiralcodes/trust-scanner@<pinned version>`), passes your arguments through and returns the CLI's exit code. It needs Node 18+ on the machine; the first run downloads the npm package (not your code). Keeping one implementation means the Python and Node results cannot drift apart. Details: `python/README.md`.

## MCP server

`spiral-trust-scanner` is an MCP server on stdio. Start it with `npx -y @spiralcodes/trust-scanner mcp` (or the `spiral-trust-scanner` bin; from a clone, `node mcp/server.mjs`).

```json
{
  "mcpServers": {
    "spiral-trust-scanner": {
      "command": "npx",
      "args": ["-y", "@spiralcodes/trust-scanner", "mcp"],
      "env": { "SPIRAL_TRUST_ALLOWED_ROOTS": "/path/to/your/projects" }
    }
  }
}
```

| Tool | What it does |
| --- | --- |
| `scan_path` | Runs the local scan on a path (`path`, optional `mode`, `fail_on`) and returns counts, findings, `target_hash` and `findings_hash`. Offline. It only reads under `SPIRAL_TRUST_ALLOWED_ROOTS` (default: the server's working directory) and does not follow symlinks. |
| `verify_receipt` | Verifies the Ed25519 signature of a Spiral receipt. Pass the receipt JSON (fully offline) or a `receipt_id` (one GET to the issuer for the public receipt). The signature is checked locally against the issuer public key pinned in this package (the key in this README), or one you pass as `public_key`. |

Not implemented, and therefore not exposed: `check_claim` and `generate_dispute_dossier`. They are roadmap items that live in Spiral Truth, not in this package.

`mcp/server.json` is the manifest for the Official MCP Registry (name `io.github.reimsfreitas-alt/spiral-trust-scanner`). It was checked offline against the registry's published `server.schema.json`; it has not been accepted by the live registry yet (see `PUBLISHING.md`).

## Receipts and badge

A receipt is **opt-in**. A plain scan sends nothing. With `--receipt` (or `receipt: true` in the Action) the scan still runs locally, and then the client POSTs this to the receipt service:

```
scanner_version, target_hash, findings_hash,
counts {critical, high, medium, low}, threshold, files_scanned,
source {repo, commit}   # only with --include-source
```

No file paths, no source code and no finding text are sent. The service answers with a receipt id, an issue time, an Ed25519 signature, a validation URL and a badge URL, which the CLI prints and the Job Summary shows.

**What a receipt attests.** That the service received this digest at that time and signed that fact. It is **not proof that the code is secure**, not a certification and not a clean bill of health: the scan is a heuristic, and the digest says nothing about the files that did not fit the scan window. A receipt is best-effort: if the service cannot be reached, you get a warning, and the scan result and exit code are exactly what they would have been without it.

**Badge.** The CLI and the Job Summary print Markdown such as `[![Spiral Trust Scan receipt](<badge_url>)](<validation_url>)`. It is never inserted automatically: you decide whether to paste it into a README. Do not add it to repositories you do not own without the owner's agreement.

To check a receipt yourself, see [A claim you can check](#a-claim-you-can-check) and the `verify_receipt` tool.

## Measured precision (read before trusting a finding)

We ran this scanner file by file over 11 public agent/MCP repositories (2,285 source files) to see how it behaves outside our own tests. What we found:

- The heuristic works per file, with keyword matching. It cannot see an authorization gate that lives in another file, so `authorization-gap` and `unverifiable-effect` often fire on HTTP helpers, telemetry, CLI code and demo apps that simply call `fetch`. Treat those two as "look here", not "this is a vulnerability".
- `secret-exposure` had false positives on prefix constants (`"ghp_"`), placeholders (`sk_test_xxx`) and header names. These are fixed and covered by a regression test; some residual false positives are still possible.
- We did not publish "X% of projects are vulnerable" numbers, because this method cannot support them.

Treat every finding as a pointer for a human to check.

## Same analysis as the free web scanner

The core is the same analysis the free web scanner runs. If you prefer a page to a terminal, paste code at https://spiral-os-matrix-current.vercel.app/#trust-scanner and you get a shareable result link.

Want a person to read your results? A one-off written review is available from the same page.

## Tests

```
npm test
```

The suite covers the receipt client against a local mock of the server contract (including network failure), hashing determinism, the Job Summary and outputs writer, SARIF shape, a scripted MCP session, the tarball contents (`npm pack --dry-run`, plus an install of the tarball), and the no-network check: every source file except `src/receipt-client.mjs` is checked for network code, that file is the one exemption by explicit name, and nothing may import it statically. The Python launcher has its own tests (`python -m unittest discover -s python/tests`).

## License

MIT. See `LICENSE`.

## A claim you can check

Spiral's verification service issued a signed receipt for one claim about this repository: *it is public and MIT-licensed*. The service fetched GitHub's public API itself, applied three rules, and recorded the result in an append-only, hash-chained ledger (receipt `rcpt_6b9e7440-d7a6-4525-bf63-698ec209dd52`).

**Check it yourself, offline.** The receipt carries an Ed25519 signature. The issuer's public key is published at `/api/v1/public/key`, so you do not have to ask the issuer whether its own receipt is genuine:

```
curl -s "https://spiral-os-matrix-current.vercel.app/api/v1/public/receipt?id=rcpt_6b9e7440-d7a6-4525-bf63-698ec209dd52" > receipt.json
node bin/verify-receipt.mjs receipt.json \
  --signature ed25519:290ddd162e4c7c169e135f4960cdf44a7eadd03fc03cca686c55789293636da388ee6e9ddf60c733e1b9f8e96287b48a4d1e8f67a3e6b791a26a89bc2726d50c \
  --public-key MCowBQYDK2VwAyEALriybIkO1GdZ/3SNB+vccalGzaNDxmiiU+hdEzD4EzE=
```

The script uses only `node:crypto`. Change one character of the payload or the signature and it prints `NOT AUTHENTIC`. There is also an online check with no key: `...?id=<id>&signature=<signature>` returns `"authentic": true|false`.

**What this does and does not show.** It shows that this issuer signed this exact result and that the ledger entry is chained after the previous one. It does not show that the issuer is honest, and it does not make the evidence true: evidence marked `provided` is self-reported by whoever submits it, and `http` evidence is whatever the URL returned when the issuer fetched it. The ledger is not yet anchored anywhere public, so the issuer could in principle rewrite history; publishing the ledger head in a public repository is the next step. This is a reference receipt issued by the project itself, not a customer case. The scanner above is a heuristic and proves nothing about your code.
