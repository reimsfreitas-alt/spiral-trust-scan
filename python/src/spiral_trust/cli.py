"""spiral-trust: a thin wrapper around the Node.js CLI ``@spiralcodes/trust-scanner``.

It does not re-implement the scan. It finds Node, runs the real CLI with your arguments and
returns its exit code unchanged (0 below the threshold, 1 at or above it, 2 usage error).
This wrapper adds one more code, 127, when neither ``npx`` nor an override command is found.

How the command is chosen, in order:
  1. ``SPIRAL_TRUST_BIN`` (a command, split like a shell would), e.g. ``trust-scan`` for a global install.
  2. ``npx --yes @spiralcodes/trust-scanner@<version pinned in this wrapper>``. The first run
     downloads that npm package; your code is not uploaded. ``SPIRAL_TRUST_NPX_SPEC`` overrides the spec.
  3. A ``trust-scan`` executable on PATH.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from typing import List, Optional, Sequence

NODE_PACKAGE = "@spiralcodes/trust-scanner"
# Keep equal to the version in python/pyproject.toml and package.json (a test checks it).
NODE_PACKAGE_VERSION = "0.2.0"


def build_command(argv: Sequence[str], env: Optional[dict] = None) -> Optional[List[str]]:
    env = os.environ if env is None else env
    override = env.get("SPIRAL_TRUST_BIN", "").strip()
    if override:
        return [*shlex.split(override), *argv]
    npx = shutil.which("npx", path=env.get("PATH"))
    if npx:
        spec = env.get("SPIRAL_TRUST_NPX_SPEC") or f"{NODE_PACKAGE}@{NODE_PACKAGE_VERSION}"
        return [npx, "--yes", spec, *argv]
    local = shutil.which("trust-scan", path=env.get("PATH"))
    if local:
        return [local, *argv]
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = build_command(args)
    if cmd is None:
        sys.stderr.write(
            "spiral-trust: Node.js is required (this package only launches the Node CLI).\n"
            "Install Node 18+ so that `npx` is on PATH, or install @spiralcodes/trust-scanner "
            "and set SPIRAL_TRUST_BIN=trust-scan.\n"
        )
        return 127
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 130
    except OSError as err:
        sys.stderr.write(f"spiral-trust: could not run {cmd[0]}: {err}\n")
        return 127


if __name__ == "__main__":
    sys.exit(main())
