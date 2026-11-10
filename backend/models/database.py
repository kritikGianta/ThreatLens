"""
Database engine and session management.

PostgreSQL is the production database (see docker-compose.yml). SQLite is supported
for zero-dependency local development and for the test-suite.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from config import settings


def build_database_url() -> str:
    if settings.DATABASE_URL:
        url = settings.DATABASE_URL
        # Normalise common Postgres URL spellings to the psycopg v3 driver.
        if url.startswith("postgres://"):
            url = "postgresql+psycopg://" + url[len("postgres://"):]
        elif url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://"):]
        return url

    if settings.DB_BACKEND in {"postgres", "postgresql"}:
        if not settings.DB_PASSWORD:
            raise ValueError("DB_PASSWORD is required when DB_BACKEND=postgres")
        return (
            f"postgresql+psycopg://{settings.DB_USER}:{quote_plus(settings.DB_PASSWORD)}"
            f"@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
        )

    sqlite_path = Path(settings.SQLITE_PATH)
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{sqlite_path.as_posix()}"


DATABASE_URL = build_database_url()
IS_SQLITE = DATABASE_URL.startswith("sqlite")

if IS_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False, "timeout": 30},
        pool_pre_ping=True,
    )

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
        # Let SQLAlchemy manage transactions so SAVEPOINTs (begin_nested) work with pysqlite.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    @event.listens_for(engine, "begin")
    def _sqlite_begin(connection):  # pragma: no cover - driver hook
        connection.exec_driver_sql("BEGIN")
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=1800,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
Base = declarative_base()


_MIGRATION_LOCK_ID = 727274  # arbitrary constant for pg_advisory_lock


def init_db() -> None:
    """
    Bring the schema up to date.
    - PostgreSQL: run Alembic migrations (`upgrade head`) under an advisory lock so
      several API replicas can start concurrently. Databases created before
      migrations existed are stamped first.
    - SQLite (local dev / tests): create tables directly.
    """
    import models.db_models  # noqa: F401  (register models on Base.metadata)

    if IS_SQLITE:
        Base.metadata.create_all(bind=engine)
        return

    from alembic import command
    from alembic.config import Config

    backend_dir = Path(__file__).resolve().parents[1]
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "migrations"))
    cfg.attributes["configure_logger"] = False

    with engine.connect() as lock_conn:
        lock_conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _MIGRATION_LOCK_ID})
        try:
            inspector = inspect(engine)
            if not inspector.has_table("alembic_version") and inspector.has_table("users"):
                command.stamp(cfg, "head")
            command.upgrade(cfg, "head")
        finally:
            lock_conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _MIGRATION_LOCK_ID})
            lock_conn.commit()


def check_database() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def safe_database_url() -> str:
    """DATABASE_URL with the password masked, for logs."""
    return engine.url.render_as_string(hide_password=True)
