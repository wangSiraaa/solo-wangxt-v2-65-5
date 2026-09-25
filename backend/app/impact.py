"""
RIB snapshots + impact-analysis task lifecycle (DB orchestration).

* import_rib: validate -> dedupe -> atomically freeze one RIB snapshot.
  Re-importing the same collection (same neighbor/family/collected_at/
  source_version AND same content hash) is idempotent; the same collection
  identity with DIFFERENT content is a conflict.  A collection older than
  what we already hold is stored as a historical version (is_latest=False)
  and never displaces the newer one.
* impact tasks bind their complete input (RIB + two policy snapshots) via
  input_fingerprint, run synchronously through a pending/running/done|failed
  state machine, and are retryable from failed/pending.  A done task is
  final: its result is never rewritten, so later policy edits or newer RIB
  imports cannot cross-version (串版) it.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
from typing import List, Optional, Sequence, Tuple, Union

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import db as dbmod
from .frr_bridge import FRRBridge
from .rib import (
    RibEntry, compute_impact, parse_rib_routes,
    rib_content_hash, task_fingerprint,
)
from .service import ValidationError, engine_policy_from_snapshot
from .validate import cross_validate

TASK_PENDING = "pending"
TASK_RUNNING = "running"
TASK_DONE = "done"
TASK_FAILED = "failed"


class RibConflictError(ValueError):
    """Same collection identity, different content (HTTP 409)."""


def _utc_naive(d: dt.datetime) -> dt.datetime:
    """Normalize to naive UTC so collection instants compare/dedupe cleanly."""
    if d.tzinfo is not None:
        d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return d


# ---------------------------------------------------------------------------
# RIB import
# ---------------------------------------------------------------------------

def import_rib(session: Session, *,
               family: int,
               collected_at: dt.datetime,
               source_version: str,
               routes: Sequence[Union[str, dict]],
               neighbor_id: Optional[int] = None,
               neighbor_name: Optional[str] = None,
               label: str = "",
               ) -> Tuple[dbmod.RibSnapshot, bool, int]:
    """
    Atomically freeze one RIB snapshot.  Returns (snapshot, created,
    collapsed_duplicates).  Any illegal line -> RibImportError and NOTHING
    is persisted (single transaction).
    """
    nb = None
    if neighbor_id is not None:
        nb = session.get(dbmod.Neighbor, neighbor_id)
    elif neighbor_name:
        nb = session.query(dbmod.Neighbor).filter_by(name=neighbor_name).first()
    if nb is None:
        raise ValidationError(
            f"unknown neighbor {neighbor_name or neighbor_id!r}; "
            "create it under /api/neighbors first")

    entries, collapsed = parse_rib_routes(family, routes)
    chash = rib_content_hash(entries)
    collected = _utc_naive(collected_at)

    existing = session.query(dbmod.RibSnapshot).filter_by(
        neighbor_id=nb.id, family=family, collected_at=collected,
        source_version=source_version).first()
    if existing is not None:
        if existing.content_hash != chash:
            raise RibConflictError(
                f"collection {source_version!r} @ {collected.isoformat()} for "
                f"neighbor {nb.name!r} already exists with DIFFERENT content "
                f"(hash {existing.content_hash[:12]}… vs {chash[:12]}…); "
                "use a new source_version for a corrected re-collection")
        return existing, False, collapsed          # idempotent re-import

    snap = dbmod.RibSnapshot(
        neighbor_id=nb.id, family=family, label=label,
        source_version=source_version, collected_at=collected,
        status="frozen", route_count=len(entries), content_hash=chash,
    )
    session.add(snap)
    session.flush()                                   # assign id
    session.add_all([
        dbmod.RibRoute(snapshot_id=snap.id, ordinal=e.ordinal,
                       prefix=e.prefix, next_hop=e.next_hop, family=family)
        for e in entries
    ])
    session.commit()                                  # single atomic freeze
    session.refresh(snap)
    return snap, True, collapsed


def _latest_collected(session: Session, neighbor_id: int, family: int):
    return session.scalar(
        select(func.max(dbmod.RibSnapshot.collected_at))
        .where(dbmod.RibSnapshot.neighbor_id == neighbor_id,
               dbmod.RibSnapshot.family == family))


def rib_dict(session: Session, snap: dbmod.RibSnapshot,
             include_routes: bool = False) -> dict:
    latest = _latest_collected(session, snap.neighbor_id, snap.family)
    is_latest = latest is not None and snap.collected_at >= latest
    d = {
        "id": snap.id,
        "neighbor_id": snap.neighbor_id,
        "neighbor": snap.neighbor.name if snap.neighbor else None,
        "family": snap.family,
        "label": snap.label,
        "source_version": snap.source_version,
        "collected_at": snap.collected_at.isoformat(),
        "imported_at": snap.imported_at.isoformat() if snap.imported_at else None,
        "status": snap.status,
        "route_count": snap.route_count,
        "content_hash": snap.content_hash,
        "is_latest": is_latest,
        "latest_collected_at": latest.isoformat() if latest else None,
    }
    if include_routes:
        d["routes"] = [
            {"ordinal": r.ordinal, "prefix": r.prefix, "next_hop": r.next_hop}
            for r in sorted(snap.routes, key=lambda r: r.ordinal)
        ]
    return d


# ---------------------------------------------------------------------------
# Impact tasks
# ---------------------------------------------------------------------------

def _get_rib(session: Session, rib_id: int) -> dbmod.RibSnapshot:
    rib = session.get(dbmod.RibSnapshot, rib_id)
    if rib is None:
        raise ValidationError(f"RIB snapshot {rib_id} not found")
    return rib


def _get_snap(session: Session, sid: int) -> dbmod.Snapshot:
    snap = session.get(dbmod.Snapshot, sid)
    if snap is None:
        raise ValidationError(f"policy snapshot {sid} not found")
    return snap


def create_task(session: Session, rib_id: int, old_sid: int, new_sid: int,
                ) -> Tuple[dbmod.ImpactTask, bool]:
    """Get-or-create the task for this exact input triple."""
    rib = _get_rib(session, rib_id)
    old_snap = _get_snap(session, old_sid)
    new_snap = _get_snap(session, new_sid)
    for tag, snap in (("old", old_snap), ("new", new_snap)):
        pfam = snap.payload.get("family")
        if pfam != rib.family:
            raise ValidationError(
                f"address family mismatch: RIB is IPv{rib.family} but {tag} "
                f"policy snapshot {snap.id} ({snap.payload.get('name')!r}) is "
                f"IPv{pfam}; IPv4 and IPv6 are analyzed separately")

    task = session.query(dbmod.ImpactTask).filter_by(
        rib_snapshot_id=rib.id, old_snapshot_id=old_snap.id,
        new_snapshot_id=new_snap.id).first()
    if task is not None:
        return task, False

    task = dbmod.ImpactTask(
        rib_snapshot_id=rib.id, old_snapshot_id=old_snap.id,
        new_snapshot_id=new_snap.id,
        status=TASK_PENDING,
        input_fingerprint=task_fingerprint(
            rib.content_hash, old_snap.payload, new_snap.payload),
    )
    session.add(task)
    session.commit()
    session.refresh(task)
    return task, True


def _rib_entries(rib: dbmod.RibSnapshot) -> List[RibEntry]:
    return [RibEntry(ordinal=r.ordinal, prefix=r.prefix, next_hop=r.next_hop)
            for r in sorted(rib.routes, key=lambda r: r.ordinal)]


def _provenance(rib: dbmod.RibSnapshot, old_snap: dbmod.Snapshot,
                new_snap: dbmod.Snapshot, fingerprint: str) -> dict:
    return {
        "rib": {
            "id": rib.id,
            "neighbor": rib.neighbor.name if rib.neighbor else None,
            "neighbor_id": rib.neighbor_id,
            "family": rib.family,
            "collected_at": rib.collected_at.isoformat(),
            "source_version": rib.source_version,
            "content_hash": rib.content_hash,
            "route_count": rib.route_count,
        },
        "old_snapshot": {
            "id": old_snap.id, "policy_id": old_snap.policy_id,
            "policy": old_snap.payload.get("name"),
            "version": old_snap.version, "label": old_snap.label,
        },
        "new_snapshot": {
            "id": new_snap.id, "policy_id": new_snap.policy_id,
            "policy": new_snap.payload.get("name"),
            "version": new_snap.version, "label": new_snap.label,
        },
        "input_fingerprint": fingerprint,
    }


def run_task(session: Session, task: dbmod.ImpactTask) -> dbmod.ImpactTask:
    """
    Execute (or re-execute) a pending/failed task.  Done tasks are final and
    rejected by the caller.  The bound inputs are re-fingerprinted before
    computing: if anything no longer matches what the task was created with,
    the run fails instead of writing a cross-versioned result.
    """
    task.status = TASK_RUNNING
    task.attempts = (task.attempts or 0) + 1
    task.started_at = dbmod.utcnow()
    task.finished_at = None
    task.error = None
    session.commit()
    try:
        rib = _get_rib(session, task.rib_snapshot_id)
        old_snap = _get_snap(session, task.old_snapshot_id)
        new_snap = _get_snap(session, task.new_snapshot_id)
        fp = task_fingerprint(rib.content_hash, old_snap.payload,
                              new_snap.payload)
        if fp != task.input_fingerprint:
            raise ValidationError(
                "bound inputs no longer match the task fingerprint; refusing "
                "to write a cross-versioned result")

        result = compute_impact(
            _rib_entries(rib),
            engine_policy_from_snapshot(old_snap),
            engine_policy_from_snapshot(new_snap),
        )
        result["inputs"] = _provenance(rib, old_snap, new_snap, fp)
        task.result = result
        task.status = TASK_DONE
        task.error = None
    except Exception as e:                              # noqa: BLE001 - persisted
        task.result = None
        task.status = TASK_FAILED
        task.error = f"{type(e).__name__}: {e}"
    task.finished_at = dbmod.utcnow()
    session.commit()
    session.refresh(task)
    return task


def retry_task(session: Session, task_id: int) -> dbmod.ImpactTask:
    task = session.get(dbmod.ImpactTask, task_id)
    if task is None:
        raise ValidationError(f"impact task {task_id} not found")
    if task.status == TASK_DONE:
        raise RibConflictError(
            "task is done; results are immutable and cannot be re-run")
    return run_task(session, task)


def task_dict(session: Session, task: dbmod.ImpactTask,
              include_result: bool = True) -> dict:
    rib = session.get(dbmod.RibSnapshot, task.rib_snapshot_id)
    old_snap = session.get(dbmod.Snapshot, task.old_snapshot_id)
    new_snap = session.get(dbmod.Snapshot, task.new_snapshot_id)
    d = {
        "id": task.id,
        "status": task.status,
        "attempts": task.attempts,
        "error": task.error,
        "rib_snapshot_id": task.rib_snapshot_id,
        "old_snapshot_id": task.old_snapshot_id,
        "new_snapshot_id": task.new_snapshot_id,
        "input_fingerprint": task.input_fingerprint,
        "inputs": (_provenance(rib, old_snap, new_snap, task.input_fingerprint)
                   if (rib and old_snap and new_snap) else None),
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "finished_at": (task.finished_at.isoformat()
                        if task.finished_at else None),
    }
    if include_result:
        d["result"] = task.result
    return d


# ---------------------------------------------------------------------------
# FRR cross-validation of a limited RIB sample
# ---------------------------------------------------------------------------

def cross_validate_impact(session: Session, task_id: int, node: str = "a",
                          limit: int = 50,
                          bridge: Optional[FRRBridge] = None) -> dict:
    """
    Push the task's NEW policy snapshot to a local FRR container and compare
    a LIMITED sample of the RIB (changed routes first — they carry the
    review risk).  The run is persisted in `runs` with the task link so the
    container evidence stays replayable.
    """
    task = session.get(dbmod.ImpactTask, task_id)
    if task is None:
        raise ValidationError(f"impact task {task_id} not found")
    if task.status != TASK_DONE or not task.result:
        raise ValidationError("task is not done; nothing to cross-validate")
    new_snap = _get_snap(session, task.new_snapshot_id)

    rows = sorted(task.result["rows"],
                  key=lambda r: (not r["changed"], r["ordinal"]))
    sample = rows[:max(1, limit)]
    probes = [r["prefix"] for r in sample]

    policy = engine_policy_from_snapshot(new_snap)
    result = cross_validate(policy, probes, node=node, bridge=bridge)
    run = dbmod.Run(
        snapshot_id=new_snap.id, node=node, status=result["status"],
        impact_task_id=task.id,
        detail={
            "impact_task_id": task.id,
            "rib_snapshot_id": task.rib_snapshot_id,
            "sample_strategy": "changed-first",
            "sample_size": len(probes),
            "mismatch_count": result["mismatch_count"],
            "probes": probes,
            "mismatches": result["mismatches"],
            "setup_error": result.get("setup_error"),
        },
    )
    session.add(run)
    session.commit()
    result["run_id"] = run.id
    result["impact_task_id"] = task.id
    result["sample"] = [{"prefix": r["prefix"], "changed": r["changed"]}
                        for r in sample]
    return result


def task_runs(session: Session, task_id: int) -> List[dict]:
    runs = session.query(dbmod.Run).filter_by(impact_task_id=task_id) \
        .order_by(dbmod.Run.created_at.desc()).all()
    return [{
        "id": r.id, "snapshot_id": r.snapshot_id, "node": r.node,
        "status": r.status, "detail": r.detail,
        "created_at": r.created_at.isoformat(),
    } for r in runs]


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_task_json(session: Session, task: dbmod.ImpactTask) -> dict:
    """Self-contained, replayable export: inputs + provenance + result +
    FRR container evidence."""
    d = task_dict(session, task, include_result=True)
    d["frr_runs"] = task_runs(session, task.id)
    d["export_kind"] = "rib-impact-analysis/v1"
    return d


def export_task_csv(task: dbmod.ImpactTask) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ordinal", "prefix", "next_hop", "old_action", "old_seq",
                "new_action", "new_seq", "changed"])
    rows = (task.result or {}).get("rows", [])
    for r in rows:
        w.writerow([
            r["ordinal"], r["prefix"], r["next_hop"],
            r["old"]["action"], r["old"]["seq"] if r["old"]["seq"] is not None else "default",
            r["new"]["action"], r["new"]["seq"] if r["new"]["seq"] is not None else "default",
            "yes" if r["changed"] else "no",
        ])
    return buf.getvalue()
