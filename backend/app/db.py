"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs.

Also the RIB-snapshot / impact-analysis additions:

* ``RibSnapshot``  frozen, deduplicated, offline RIB capture (neighbor,
  family, collected_at, source/version metadata + content hashes).  A late
  RIB is only ever a new *historical* version (``stale`` flag); it can never
  overwrite a frozen one.
* ``RibRoute``     one reachable prefix entry (prefix, nexthop, family).
* ``ImpactTask``   a job bound to the COMPLETE, frozen inputs (two policy
  snapshots + one RIB snapshot by id, plus an input digest).  Results are
  stored inline and keyed by that digest, so concurrent policy/RIB edits
  cannot change a finished or in-flight result (no cross-version leakage).
"""
from __future__ import annotations

import datetime as dt
from typing import List

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, select,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Neighbor(Base):
    __tablename__ = "neighbors"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ip: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer, default=4)
    asn: Mapped[int] = mapped_column(Integer, nullable=True)
    inbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outbound_policy: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    family: Mapped[int] = mapped_column(Integer, default=4)       # 4 or 6
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    description: Mapped[str] = mapped_column(String(256), default="")
    draft: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)

    rules: Mapped[List["Rule"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        order_by="Rule.seq",
    )
    snapshots: Mapped[List["Snapshot"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan",
        order_by="Snapshot.version.desc()",
    )


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("policy_id", "seq", name="uq_policy_seq"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    seq: Mapped[int] = mapped_column(Integer)
    prefix: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(8))                  # permit/deny
    ge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    le: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remark: Mapped[str] = mapped_column(String(256), default="")

    policy: Mapped[Policy] = relationship(back_populates="rules")


class Snapshot(Base):
    """
    Immutable configuration snapshot.  payload is the exact, replayable
    policy body: ordered rules + default action + family, plus FRR-rendered
    config and metadata.  Replays never depend on later edits.
    """
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    label: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict] = mapped_column(JSON)
    frr_config: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="lab")

    policy: Mapped[Policy] = relationship(back_populates="snapshots")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)


class Scenario(Base):
    """Saved replay bundle: from/to snapshots, probe inputs, observed results."""
    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    from_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    to_snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    probes: Mapped[list] = mapped_column(JSON, default=list)   # ordered prefix list
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Run(Base):
    """One cross-validation run against a local FRR container."""
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("snapshots.id"), nullable=True)
    node: Mapped[str] = mapped_column(String(16), default="a")      # router-a/b
    status: Mapped[str] = mapped_column(String(16), default="ok")   # ok/mismatch/error
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------
# RIB snapshots (offline imports; never pulled from a live router here)
# --------------------------------------------------------------------------

class RibSnapshot(Base):
    """
    An atomically frozen, deduplicated offline RIB capture.

    `source`/`source_version` identify where the capture came from (e.g. an
    exported `show ip bgp` file and the router version), `collected_at` is
    the capture timestamp claimed by the import.  `content_hash` covers the
    exact, canonicalized route set: repeating an identical import returns
    the same row without duplicating routes.

    `frozen` flips on only after the whole batch validated and committed, so
    an illegal row fails the ENTIRE import and leaves no partial snapshot.
    A RIB arriving with an older `collected_at` than the newest snapshot for
    the same neighbor/family is accepted purely as history (`stale=True`)
    and never replaces anything.
    """
    __tablename__ = "rib_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    neighbor: Mapped[str] = mapped_column(String(64), default="")
    family: Mapped[int] = mapped_column(Integer)                 # 4 or 6 only
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime)
    source: Mapped[str] = mapped_column(String(128), default="")
    source_version: Mapped[str] = mapped_column(String(128), default="")
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    route_count: Mapped[int] = mapped_column(Integer, default=0)
    stale: Mapped[bool] = mapped_column(Boolean, default=False)
    frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_import: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    routes: Mapped[List["RibRoute"]] = relationship(
        back_populates="rib", cascade="all, delete-orphan",
        order_by="RibRoute.id",
    )


class RibRoute(Base):
    """One reachable prefix of a frozen RIB snapshot."""
    __tablename__ = "rib_routes"
    __table_args__ = (
        UniqueConstraint("rib_id", "prefix", "nexthop", name="uq_rib_route"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    rib_id: Mapped[int] = mapped_column(
        ForeignKey("rib_snapshots.id", ondelete="CASCADE"))
    prefix: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer)
    nexthop: Mapped[str] = mapped_column(String(64), default="")
    # raw line kept for audit/replay of the imported evidence
    raw: Mapped[str] = mapped_column(String(512), default="")

    rib: Mapped[RibSnapshot] = relationship(back_populates="routes")


class ImpactTask(Base):
    """
    An impact-analysis job bound to its COMPLETE inputs: two immutable
    policy snapshots + one frozen RIB snapshot, referenced by id and pinned
    by `input_digest` (canonical hashes of all three payloads).  The engine
    recomputes/verifies the digest before reading any payload, so editing a
    live policy or importing another RIB while the task runs cannot change
    the result.  A failed task keeps `status='failed'` with the error and is
    retryable; retries recompute from the same frozen inputs and produce the
    same result — versions never bleed into each other.
    """
    __tablename__ = "impact_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    old_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    new_snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    rib_snapshot_id: Mapped[int] = mapped_column(ForeignKey("rib_snapshots.id"))
    input_digest: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # pending -> running -> succeeded / failed (retry resets to pending)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow)


class ImpactEvidence(Base):
    """
    FRR container evidence gathered for an impact task's LIMITED sample.
    Kept separately from the computed result so raw container output stays
    auditable/replayable across API restarts and task retries.
    """
    __tablename__ = "impact_evidences"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("impact_tasks.id", ondelete="CASCADE"))
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshots.id"))
    node: Mapped[str] = mapped_column(String(16), default="a")
    status: Mapped[str] = mapped_column(String(16), default="ok")
    sample_size: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


def init_db() -> None:
    # New tables (rib_snapshots / rib_routes / impact_tasks) are created
    # here for databases initialized before this feature; create_all is
    # idempotent on existing tables.  The versioned migration runner below
    # then handles additive DDL / data migrations once each.
    Base.metadata.create_all(engine)
    _run_migrations(engine)


def get_session() -> Session:
    return SessionLocal()


# --------------------------------------------------------------------------
# Dependency-free, versioned migration runner (SQLite + PostgreSQL).
#
# Each migration is (version, statements-by-dialect).  Additive DDL only;
# every statement must be idempotent so an interrupted boot can safely
# re-run.  Applied versions are recorded in `schema_migrations`.
# --------------------------------------------------------------------------

_MIGRATIONS = [
    # 0001: RIB snapshot import + impact analysis.  The three tables are
    # created by Base.metadata.create_all(); this entry marks the feature
    # level and provides a hook for pre-existing databases that need
    # additive indexes/columns later.
    ("0001_rib_impact", {
        "sqlite": [
            "CREATE INDEX IF NOT EXISTS ix_rib_routes_rib_id "
            "ON rib_routes (rib_id)",
            "CREATE INDEX IF NOT EXISTS ix_impact_tasks_digest "
            "ON impact_tasks (input_digest)",
        ],
        "postgresql": [
            "CREATE INDEX IF NOT EXISTS ix_rib_routes_rib_id "
            "ON rib_routes (rib_id)",
            "CREATE INDEX IF NOT EXISTS ix_impact_tasks_digest "
            "ON impact_tasks (input_digest)",
        ],
    }),
]


def _run_migrations(db_engine) -> None:
    from sqlalchemy import text
    dialect = db_engine.dialect.name
    with db_engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version VARCHAR(64) PRIMARY KEY, applied_at TIMESTAMP)"))
        applied = {
            row[0] for row in
            conn.execute(text("SELECT version FROM schema_migrations"))
        }
    for version, stmts in _MIGRATIONS:
        if version in applied:
            continue
        with db_engine.begin() as conn:
            for sql in stmts.get(dialect, []):
                conn.execute(text(sql))
            conn.execute(
                text("INSERT INTO schema_migrations (version, applied_at) "
                     "VALUES (:v, :ts)"),
                {"v": version, "ts": utcnow()},
            )
