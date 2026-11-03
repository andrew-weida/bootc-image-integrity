#!/usr/bin/env python3
"""Exit non-zero unless a TEST_OUTPUT document records a passing integrity check.

Passing means a JSON object whose top-level "result" is SUCCESS or WARNING and whose
"failures" count is 0. Run it before signing.

usage: check-result.py TEST_OUTPUT_FILE   (- reads standard input)
"""
import json
import sys


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip())
    try:
        f = sys.stdin if sys.argv[1] == "-" else open(sys.argv[1])
        with f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        sys.exit(f"cannot read TEST_OUTPUT: {e}")

    if not isinstance(doc, dict):
        sys.exit("TEST_OUTPUT is not a JSON object")
    result = doc.get("result")
    failures = doc.get("failures")
    if result not in ("SUCCESS", "WARNING"):
        sys.exit(f"integrity result is {result!r}, not SUCCESS or WARNING")
    if failures != 0 or isinstance(failures, bool):
        sys.exit(f"integrity check reported failures: {failures!r}")
    print(f"integrity result {result}, 0 failures")


if __name__ == "__main__":
    main()
