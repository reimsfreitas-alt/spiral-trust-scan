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
