"""Bounded in-process worker for development and single-node deployments.

The worker stores every state transition in SQL. It is intentionally an adapter seam:
multi-node deployments can replace this module with Celery/RQ without changing the
job API or domain tasks.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from ..config import get_settings
from ..database.repository import JobRepository
from ..database.session import get_session_factory


class JobCancelled(Exception):
    """Cooperative cancellation signal raised inside a task."""


def _repository_call(callback):
    session = get_session_factory()()
    try:
        return callback(JobRepository(session))
    finally:
        session.close()


@dataclass(frozen=True, slots=True)
class JobContext:
    job_id: str

    def update(self, progress: int, message: str) -> None:
        if self.cancelled():
            raise JobCancelled
        _repository_call(
            lambda repository: repository.update(
                self.job_id, progress=progress, message=message
            )
        )

    def cancelled(self) -> bool:
        return bool(
            _repository_call(
                lambda repository: repository.get(self.job_id).cancel_requested
            )
        )

    def check_cancelled(self) -> None:
        if self.cancelled():
            raise JobCancelled


_executor: ThreadPoolExecutor | None = None
_lock = threading.Lock()
_futures: dict[str, Future] = {}


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=get_settings().max_concurrent_jobs,
                thread_name_prefix="rlab-analysis",
            )
        return _executor


def submit_job(job_id: str, task: Callable[[JobContext], str | None]) -> None:
    """Submit a task whose return value is a persisted result reference."""

    def run() -> None:
        context = JobContext(job_id)
        try:
            context.check_cancelled()
            _repository_call(
                lambda repository: repository.update(
                    job_id, state="running", progress=1, message="Analysis started"
                )
            )
            result_ref = task(context)
            context.check_cancelled()
            _repository_call(
                lambda repository: repository.update(
                    job_id,
                    state="completed",
                    progress=100,
                    message="Analysis complete",
                    result_ref=result_ref,
                )
            )
        except JobCancelled:
            _repository_call(
                lambda repository: repository.update(
                    job_id,
                    state="cancelled",
                    message="Cancellation acknowledged",
                )
            )
        except Exception as exc:  # task errors become structured terminal state
            _repository_call(
                lambda repository: repository.update(
                    job_id,
                    state="failed",
                    message="Analysis failed",
                    error=f"{exc.__class__.__name__}: {exc}",
                )
            )
        finally:
            with _lock:
                _futures.pop(job_id, None)

    executor = _get_executor()
    with _lock:
        future = executor.submit(run)
        _futures[job_id] = future


def cancel_job(job_id: str) -> None:
    record = _repository_call(lambda repository: repository.request_cancel(job_id))
    with _lock:
        future = _futures.get(job_id)
    if future is not None and record.state == "cancelled":
        future.cancel()
