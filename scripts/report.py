#!/usr/bin/env python3
"""Summarize `conftest test --output json` results.

Prints one line per finding, optionally writes a TEST_OUTPUT result (the JSON shape
Konflux-style pipelines use for test tasks), and exits non-zero on failures.

usage: report.py CONFTEST_JSON [--test-output FILE] [--fail-on-violation true|false]
exit:  0 no failures (or failures not fatal), 1 failures, 2 conftest output unreadable
"""
import argparse
import datetime
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("conftest_json")
    parser.add_argument("--test-output", help="write a TEST_OUTPUT JSON result to this file")
    parser.add_argument("--fail-on-violation", default="true", choices=["true", "false"])
    args = parser.parse_args()

    try:
        with open(args.conftest_json) as f:
            results = json.load(f)
        failures = sorted(r["msg"] for res in results for r in res.get("failures") or [])
        warnings = sorted(r["msg"] for res in results for r in res.get("warnings") or [])
        successes = sum(res.get("successes", 0) for res in results)
    except (OSError, ValueError, KeyError, TypeError) as e:
        failures = warnings = None
        error = f"could not read conftest results: {e}"

    if failures is None:
        result, note, code = "ERROR", error, 2
        print(f"ERROR {error}", file=sys.stderr)
    else:
        for msg in failures:
            print(f"FAIL  {msg}")
        for msg in warnings:
            print(f"WARN  {msg}")
        result = "FAILURE" if failures else "WARNING" if warnings else "SUCCESS"
        note = f"{len(failures)} violation(s), {len(warnings)} warning(s)"
        code = 1 if failures and args.fail_on_violation == "true" else 0
        print(f"{result}: {note}")

    if args.test_output:
        output = {
            "result": result,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "namespace": "main",
            "successes": 0 if failures is None else successes,
            "failures": 0 if failures is None else len(failures),
            "warnings": 0 if failures is None else len(warnings),
            "note": note,
        }
        with open(args.test_output, "w") as f:
            json.dump(output, f, separators=(",", ":"))

    sys.exit(code)


if __name__ == "__main__":
    main()
