"""Run every delegated-authority demo scenario and print PASS/FAIL.

    python demo/public_sector_hallpass/run_demo_validation.py

Runs fully offline (in-process AWS emulator). Exit code 0 only when every
scenario matches its expected outcome. Run it before every demo.
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import logging  # noqa: E402

logging.disable(logging.WARNING)  # keep the console readable; evidence is still recorded

from api_client import OfflineSession  # noqa: E402
from scenarios import run_all  # noqa: E402


def main() -> int:
    started = time.time()
    print("=" * 78)
    print("PUBLIC SECTOR AGENT DELEGATED AUTHORITY DEMO - VALIDATION (offline)")
    print("=" * 78)
    session = OfflineSession()
    try:
        print("Provider adapters:", ", ".join(f"{k}={v}" for k, v in session.provider_modes().items()))
        print("Signing:", "AWS KMS ECC_NIST_P256 (emulated) for grants and evidence")
        print("-" * 78)

        def show(result):
            mark = "PASS" if result.passed else "FAIL"
            print(f"[{mark}] {result.number:>2}. {result.title}")
            print(f"        expected: {result.expected}")
            print(f"        outcome : {result.outcome}")
            if not result.passed:
                for step in result.steps:
                    print(f"          - {step['label']}: {step['status']} {step['detail'][:140]}")

        results = run_all(session.runner, show)
    finally:
        session.close()
    passed = sum(1 for r in results if r.passed)
    print("-" * 78)
    print(f"RESULT: {passed}/{len(results)} scenarios passed in {time.time() - started:.1f}s")
    if passed != len(results):
        print("DO NOT DEMO UNTIL EVERY SCENARIO PASSES.")
        return 1
    print("All scenarios pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
