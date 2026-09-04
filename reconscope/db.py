"""Database engine/session setup (PRD §9.3).

SQLite in WAL mode. Milestone 0 creates tables directly from the model metadata
so the app is usable immediately; Alembic migrations (wired in ``migrations/``)
become the schema authority as the model set grows.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from reconscope.config import Settings, get_settings
from reconscope.models import Base

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable WAL and foreign keys on every SQLite connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def get_engine(settings: Settings | None = None) -> Engine:
    global _engine
    if _engine is None:
        settings = settings or get_settings()
        settings.ensure_dirs()
        _engine = create_engine(
            f"sqlite:///{settings.db_path}",
            future=True,
        )
    return _engine


def init_db(settings: Settings | None = None) -> None:
    """Create tables if they do not exist."""
    Base.metadata.create_all(get_engine(settings))


def get_session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(
            bind=get_engine(settings), expire_on_commit=False, future=True
        )
    return _SessionFactory


@contextmanager
def session_scope(settings: Settings | None = None) -> Iterator[Session]:
    factory = get_session_factory(settings)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
