"""CLI for the read-only load-test harness.

    python -m loadtest --url http://127.0.0.1:8000 --path /api/health \
        --concurrency 16 --duration 30

Only GET requests to a single read-only path are issued. Point it exclusively at a
deployment you operate and are authorized to test.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .driver import run_load
from .harness import format_summary, summarize

_READ_ONLY_HINT = (
    "This harness issues only GET requests and must target a system you operate. "
    "It is a sizing tool, not a stress/DoS tool."
)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="loadtest", description="Bounded, read-only load test."
    )
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL.")
    parser.add_argument(
        "--path",
        default="/api/health",
        help="Read-only path to request (default: /api/health).",
    )
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--duration", type=float, default=15.0, help="Seconds.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request seconds.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.concurrency < 1 or args.duration <= 0:
        print("concurrency must be >= 1 and duration > 0", file=sys.stderr)
        return 2

    print(_READ_ONLY_HINT, file=sys.stderr)
    print(
        f"Load: {args.concurrency} workers x GET {args.url}{args.path} "
        f"for {args.duration}s\n",
        file=sys.stderr,
    )
    outcomes, wall = asyncio.run(
        run_load(
            base_url=args.url,
            path=args.path,
            concurrency=args.concurrency,
            duration_seconds=args.duration,
            timeout_seconds=args.timeout,
        )
    )
    if not outcomes:
        print("No responses collected; is the target reachable?", file=sys.stderr)
        return 1
    print(format_summary(summarize(outcomes, wall)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
