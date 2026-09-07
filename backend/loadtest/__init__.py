"""Bounded, read-only load-testing harness for a Reversing Lab deployment.

Not part of the API. A developer/operator tool for sizing concurrency and worker
counts against a system you are authorized to test. It issues only GET requests to
read-only endpoints; it is not a stress/DoS tool and must never target a system you do
not operate.

``harness`` holds the dependency-free statistics; ``driver`` runs the requests (httpx,
imported lazily). Run it with ``python -m loadtest --help``.
"""

from .harness import RequestOutcome, percentile, summarize

__all__ = ["RequestOutcome", "percentile", "summarize"]
