"""FastAPI application factory.

Wires configuration, logging, database initialization, CORS, the domain-error handler,
and all routers into a single app. ``uvicorn reversing_lab.api.app:app`` serves it.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from ..config import get_settings
from ..database.session import init_db
from ..logging_config import configure_logging
from .errors import register_exception_handlers
from .routes import (
    analysis,
    binaries,
    challenges,
    ctf,
    dynamic,
    health,
    integrations,
    jobs,
    memory,
    projects,
    reports,
    tooling,
    tools,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    logger.info("Reversing Lab API v%s started.", __version__)
    yield
    logger.info("Reversing Lab API shutting down.")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Reversing Lab API",
        version=__version__,
        description="Static analysis of ELF/PE/Mach-O binaries and RE challenges.",
        lifespan=_lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    api_prefix = "/api"
    app.include_router(health.router, prefix=api_prefix)
    app.include_router(binaries.router, prefix=api_prefix)
    app.include_router(analysis.router, prefix=api_prefix)
    app.include_router(projects.router, prefix=api_prefix)
    app.include_router(tools.router, prefix=api_prefix)
    app.include_router(tooling.router, prefix=api_prefix)
    app.include_router(jobs.router, prefix=api_prefix)
    app.include_router(memory.router, prefix=api_prefix)
    app.include_router(dynamic.router, prefix=api_prefix)
    app.include_router(ctf.router, prefix=api_prefix)
    app.include_router(reports.router, prefix=api_prefix)
    app.include_router(challenges.router, prefix=api_prefix)
    app.include_router(integrations.router, prefix=api_prefix)

    return app


app = create_app()
