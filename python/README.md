# spiral-trust

A thin Python launcher for the **Spiral Trust Scanner**, a local, offline, heuristic scan of agent
code and tool logs (missing authorization gate, unverifiable effect, replay risk, irreversible action
without confirmation, secrets and untrusted instructions).

**What this package is, honestly.** It is a wrapper. The scan is implemented once, in Node.js, in the npm
package [`@spiralcodes/trust-scanner`](https://github.com/reimsfreitas-alt/spiral-trust-scan). This
package finds Node, runs that CLI with your arguments and returns its exit code. It is not a Python
re-implementation, so it needs Node.js 18 or newer on the machine, and the Python and Node results
cannot drift apart.

```
pip install spiral-trust
spiral-trust path/to/agent --fail-on high
spiral-trust path/to/agent --mode deep --format sarif > trust.sarif
spiral-trust mcp          # start the MCP server on stdio
```

All CLI options are documented in the main README (`--mode quick|deep`, `--fail-on`, `--format
text|json|markdown|sarif`, `--sarif-file`, and the opt-in `--receipt`).

## How it runs the CLI

1. `SPIRAL_TRUST_BIN`, if set (for example `trust-scan` after `npm i -g @spiralcodes/trust-scanner`).
2. `npx --yes @spiralcodes/trust-scanner@<the version pinned in this wrapper>`. The first run downloads
   that npm package; your code is not uploaded anywhere by the download. Override with `SPIRAL_TRUST_NPX_SPEC`.
3. A `trust-scan` executable on `PATH`.

Exit codes are the CLI's: 0 below the threshold, 1 at or above `--fail-on`, 2 usage error. The wrapper
adds 127 when no Node launcher is found.

## Limits

The scan is a heuristic over text. It proves nothing about your code: a missing signal is not proof of a gap
and a present signal is not proof of safety. Receipts (opt-in, `--receipt`) record that two digests were
submitted at a time; they are not proof that code is secure. See the main README for measured precision.

MIT licensed.
