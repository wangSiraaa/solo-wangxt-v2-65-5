"""SQLAlchemy models: neighbors, policies + ordered rules, snapshots, runs,
RIB snapshots + routes, and impact-analysis tasks.

Schema changes go through the small versioned migration runner at the
bottom of this file (``migrate``): every migration is recorded in
``schema_migrations`` and applied exactly once, on SQLite and PostgreSQL
alike.  ``init_db`` is kept as the public entrypoint used by the API
startup, the seeder and the tests."""
from __future__ import annotations

import datetime as dt
from typing import List, Optional

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, inspect, select, text,
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
    # soft reference (no FK) to the impact task that produced this run,
    # when the run was a RIB-sample cross-validation; NULL otherwise.
    impact_task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class RibSnapshot(Base):
    """
    An immutable, atomically-frozen RIB (routing table) snapshot collected
    offline from one neighbor and one address family.

    * dedupe: routes are unique on (snapshot, prefix, next_hop); re-importing
      the same collection (same neighbor/family/collected_at/source_version)
      is idempotent and returns the existing snapshot instead of duplicating
      routes;
    * frozen: there is deliberately no update/delete path — a late-arriving
      older collection is stored as just another historical version and
      never displaces a newer one (see ``is_latest`` in impact.rib_dict).
    """
    __tablename__ = "rib_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    neighbor_id: Mapped[int] = mapped_column(
        ForeignKey("neighbors.id", ondelete="RESTRICT"))
    family: Mapped[int] = mapped_column(Integer)                    # 4 or 6
    label: Mapped[str] = mapped_column(String(128), default="")
    source_version: Mapped[str] = mapped_column(String(128))        # collector version
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime)     # 采集时间 (UTC)
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(16), default="frozen")
    route_count: Mapped[int] = mapped_column(Integer, default=0)
    content_hash: Mapped[str] = mapped_column(String(64))           # sha256 of routes

    neighbor: Mapped[Neighbor] = relationship()
    routes: Mapped[List["RibRoute"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan",
        order_by="RibRoute.ordinal")

    __table_args__ = (
        UniqueConstraint("neighbor_id", "family", "collected_at", "source_version",
                         name="uq_rib_collection"),
    )


class RibRoute(Base):
    """One deduplicated route of a frozen RIB snapshot."""
    __tablename__ = "rib_routes"

    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("rib_snapshots.id", ondelete="CASCADE"))
    ordinal: Mapped[int] = mapped_column(Integer)       # line no. of first occurrence
    prefix: Mapped[str] = mapped_column(String(64))     # canonical network
    next_hop: Mapped[str] = mapped_column(String(64))
    family: Mapped[int] = mapped_column(Integer)        # denormalized, == snapshot's

    snapshot: Mapped[RibSnapshot] = relationship(back_populates="routes")

    __table_args__ = (
        UniqueConstraint("snapshot_id", "prefix", "next_hop",
                         name="uq_rib_route"),
    )


class ImpactTask(Base):
    """
    A RIB-constrained impact-analysis task.

    The task binds its COMPLETE input at creation: one frozen RIB snapshot
    plus two immutable policy snapshots, pinned by ``input_fingerprint``
    (sha256 over the RIB content hash and both snapshot payload hashes).
    Status machine: pending -> running -> done | failed.  A failed task can
    be retried; a done task is final — its result is never rewritten, so
    later policy edits or newer RIB imports cannot cross-version (串版) it.
    """
    __tablename__ = "impact_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    rib_snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("rib_snapshots.id", ondelete="RESTRICT"))
    old_snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("snapshots.id", ondelete="RESTRICT"))
    new_snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("snapshots.id", ondelete="RESTRICT"))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    input_fingerprint: Mapped[str] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)

    rib_snapshot: Mapped[RibSnapshot] = relationship()
    old_snapshot: Mapped[Snapshot] = relationship(foreign_keys=[old_snapshot_id])
    new_snapshot: Mapped[Snapshot] = relationship(foreign_keys=[new_snapshot_id])

    __table_args__ = (
        UniqueConstraint("rib_snapshot_id", "old_snapshot_id", "new_snapshot_id",
                         name="uq_impact_inputs"),
    )


class SchemaMigration(Base):
    """Bookkeeping for the versioned migration runner below."""
    __tablename__ = "schema_migrations"

    version: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    applied_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------------------
# Versioned migrations
# ---------------------------------------------------------------------------

def _m1_core_tables() -> None:
    """Base workbench schema (neighbors/policies/rules/snapshots/scenarios/runs)."""
    Base.metadata.create_all(engine, tables=[
        Neighbor.__table__, Policy.__table__, Rule.__table__,
        Snapshot.__table__, Scenario.__table__, Run.__table__,
    ])


def _m2_rib_and_impact() -> None:
    """RIB snapshots/routes, impact tasks, runs.impact_task_id evidence link."""
    Base.metadata.create_all(engine, tables=[
        RibSnapshot.__table__, RibRoute.__table__, ImpactTask.__table__,
    ])
    cols = {c["name"] for c in inspect(engine).get_columns("runs")}
    if "impact_task_id" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE runs ADD COLUMN impact_task_id INTEGER"))


MIGRATIONS = [
    (1, "core tables", _m1_core_tables),
    (2, "rib snapshots + impact tasks + run evidence link", _m2_rib_and_impact),
]


def migrate() -> None:
    """Apply pending migrations in order; record each in schema_migrations."""
    Base.metadata.create_all(engine, tables=[SchemaMigration.__table__])
    with SessionLocal() as s:
        applied = {v for (v,) in s.execute(
            select(SchemaMigration.version)).all()}
        for version, name, fn in MIGRATIONS:
            if version in applied:
                continue
            fn()
            s.add(SchemaMigration(version=version, name=name))
            s.commit()


def init_db() -> None:
    migrate()


def recover_interrupted_tasks(session: Optional[Session] = None) -> int:
    """
    Tasks left in 'running' by a crash/restart can never finish on their own
    (execution is synchronous within a request); mark them failed so they
    become retryable.  Their bound inputs are immutable, so a retry
    reproduces the exact same analysis.
    """
    own = session is None
    s = session or SessionLocal()
    try:
        n = s.query(ImpactTask).filter(ImpactTask.status == "running").update(
            {"status": "failed",
             "error": "interrupted by service restart; safe to retry"},
            synchronize_session=False)
        s.commit()
        return n
    finally:
        if own:
            s.close()


def get_session() -> Session:
    return SessionLocal()
