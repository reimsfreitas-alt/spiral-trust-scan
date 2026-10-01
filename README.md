# Spiral Trust Scan

A local, offline scan of agent code or tool logs. It looks for five things a reviewer would ask about an AI agent that can act in the world:

1. **Authorization gap**: tool calls with external effects and no visible authorization or policy gate.
2. **Unverifiable effect**: external effects with no visible receipt, ledger or independent observation.
3. **Replay risk**: external effects with no visible idempotency or deduplication.
4. **Irreversible action without confirmation**: delete, refund, transfer, charge, publish or send with no visible confirmation or dry run.
5. **Secrets and untrusted instructions** in the scanned material.

## What it is, and what it is not

It is a **heuristic over text**. It searches for signals; it does not run your code and it proves nothing. A missing signal is not proof of a gap (your gate may live in a file that was not scanned or use a word the patterns do not know), and a present signal is not proof of safety. Treat findings as questions to answer, not verdicts.

It runs entirely on your machine. The package contains no network code, and a test in the repository fails if that ever changes.

## Use

```
node bin/trust-scan.mjs path/to/agent --fail-on high
```

Options: `--format text|json|markdown`, `--fail-on critical|high|medium|none` (default `high`), `--label name`. Exit code is 0 below the threshold, 1 at or above it, 2 on a usage error.

Limits: scans files up to 200 KB with common source and log extensions, skips `node_modules`, `.git`, build folders; the scan window is 120,000 characters, and the output says plainly how many files did not fit.

## GitHub Action

```yaml
- uses: reimsfreitas-alt/spiral-trust-scan@main
  with:
    path: .
    fail-on: high
```

The action runs the same script on the runner. Nothing is sent anywhere.

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

One of the tests checks that the package contains no network code, so the "nothing leaves your machine" claim is verified, not just stated.

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
