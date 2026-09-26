"""Run the whole pipeline on the made-up sample case: raw files -> incident report.

    python samples/run_sample.py [output-folder]      (default: out)

Checks the setup, then runs ``python -m fraud_evidence samples/case-001``.
Works the same on Windows, macOS and Linux.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "out").resolve()
    print("Checking the setup", flush=True)
    if subprocess.run([sys.executable, "-m", "fraud_evidence.check"], cwd=ROOT).returncode:
        print("\nStopped: fix the FAIL lines above and run again.")
        return 1
    print(flush=True)
    command = [sys.executable, "-m", "fraud_evidence", str(ROOT / "samples" / "case-001"),
               "--case-id", "CASE-001", "--out", str(out)]
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    sys.exit(main())
