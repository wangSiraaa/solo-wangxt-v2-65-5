"""
Impact analysis: what a policy snapshot ACTUALLY does to the reachable
prefixes handed to it by a selected, frozen RIB snapshot.

Given two policy snapshots (old/new) and ONE RIB snapshot, every reachable
RIB prefix is classified against BOTH policies (full enumeration of the
imported RIB — never a sample), producing:

    hit_old / hit_new            per-route hit chains and terminal decisions
    permitted / denied / unmatched (relative to one side's decision)
    action_changed               forwarding behavior actually flips
                                 (permit<->deny) among reachable prefixes
    decision_changed             same action but different winning rule /
                                 rule-vs-default (re-routing of the decision)
    stable                       identical decision on both snapshots

The EXISTING full-space minimal-witness analysis is computed too and carried
along unchanged — the RIB restricts impact evidence, it must NEVER replace
the semantic proof over the whole prefix space.

Inputs are pinned by id AND by a digest of the three frozen payloads.  The
digest is re-verified before execution, so editing a live policy or
importing another RIB while a task runs cannot alter the stored result.
A failed task is retryable and recomputes the same result from the same
inputs (no version cross-talk).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod
from .engine import PolicyError
from .service import ValidationError, engine_policy_from_snapshot


# --------------------------------------------------------------------------
# Input pinning
# --------------------------------------------------------------------------

def _payload_hash(snap: dbmod.Snapshot) -> str:
    body = json.dumps(
        {"payload": snap.payload, "version": snap.version,
         "policy_id": snap.policy_id},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(body.encode()).hexdigest()


def _rib_hash(rib: dbmod.RibSnapshot) -> str:
    return rib.content_hash


def _input_digest(old: dbmod.Snapshot, new: dbmod.Snapshot,
                  rib: dbmod.RibSnapshot) -> str:
    h = hashlib.sha256()
    h.update(f"snap:{old.id}:{_payload_hash(old)}\n".encode())
    h.update(f"snap:{new.id}:{_payload_hash(new)}\n".encode())
    h.update(f"rib:{rib.id}:{_rib_hash(rib)}\n".encode())
    return h.hexdigest()


def _load_bound_inputs(session: Session, task: dbmod.ImpactTask
                       ) -> Tuple[dbmod.Snapshot, dbmod.Snapshot,
                                  dbmod.RibSnapshot, str]:
    old = session.get(dbmod.Snapshot, task.old_snapshot_id)
    new = session.get(dbmod.Snapshot, task.new_snapshot_id)
    rib = session.get(dbmod.RibSnapshot, task.rib_snapshot_id)
    if old is None or new is None:
        raise ValidationError("one or both policy snapshots no longer exist")
    if rib is None or not rib.frozen:
        raise ValidationError("RIB snapshot not found or not frozen")
    digest = _input_digest(old, new, rib)
    if digest != task.input_digest:
        raise ValidationError(
            "input digest mismatch: bound inputs changed; refusing to mix "
            "versions (create a new analysis task)")
    return old, new, rib, digest


# --------------------------------------------------------------------------
# Task lifecycle
# --------------------------------------------------------------------------

def create_task(session: Session, *, old_snapshot_id: int,
                new_snapshot_id: int, rib_snapshot_id: int,
                run: bool = True) -> dbmod.ImpactTask:
    old = session.get(dbmod.Snapshot, old_snapshot_id)
    new = session.get(dbmod.Snapshot, new_snapshot_id)
    rib = session.get(dbmod.RibSnapshot, rib_snapshot_id)
    if old is None or new is None:
        raise ValidationError("snapshot not found")
    if rib is None or not rib.frozen:
        raise ValidationError("RIB snapshot not found or frozen")
    if old.payload["family"] != new.payload["family"]:
        raise ValidationError("policy snapshots belong to different families")
    if old.payload["family"] != rib.family:
        raise ValidationError(
            f"RIB is IPv{rib.family} but policy snapshots are IPv"
            f"{old.payload['family']} — families must not be mixed")

    digest = _input_digest(old, new, rib)
    # de-duplicate identical jobs: same frozen inputs -> same task, so a
    # retry/re-create can never produce a parallel "other version"
    task = session.scalar(
        select(dbmod.ImpactTask).where(
            dbmod.ImpactTask.old_snapshot_id == old_snapshot_id,
            dbmod.ImpactTask.new_snapshot_id == new_snapshot_id,
            dbmod.ImpactTask.rib_snapshot_id == rib_snapshot_id,
            dbmod.ImpactTask.input_digest == digest))
    if task is None:
        task = dbmod.ImpactTask(
            old_snapshot_id=old_snapshot_id,
            new_snapshot_id=new_snapshot_id,
            rib_snapshot_id=rib_snapshot_id,
            input_digest=digest, status="pending", attempts=0)
        session.add(task)
        session.commit()
        session.refresh(task)
    if run and task.status in ("pending", "failed"):
        run_task(session, task.id)
        session.refresh(task)
    return task


def run_task(session: Session, task_id: int) -> dbmod.ImpactTask:
    """
    Execute (or retry) a bound task.  Re-verifies the input digest against
    the frozen payloads first, then computes; success/failure is recorded on
    the same row.  A retry after failure restarts from the SAME inputs and
    yields the SAME result.
    """
    task = session.get(dbmod.ImpactTask, task_id)
    if task is None:
        raise ValidationError("task not found")
    if task.status == "running":
        return task
    if task.status == "succeeded":
        return task

    task.status = "running"
    task.attempts += 1
    task.error = None
    session.commit()
    try:
        old, new, rib, digest = _load_bound_inputs(session, task)
        result = compute_impact(old, new, rib)
        task.result = result
        task.status = "succeeded"
        task.error = None
        session.commit()
    except Exception as e:  # recorded, not lost: task stays retryable
        session.rollback()
        task = session.get(dbmod.ImpactTask, task_id)
        task.status = "failed"
        task.error = f"{type(e).__name__}: {e}"
        session.commit()
    session.refresh(task)
    return task


# --------------------------------------------------------------------------
# Pure computation
# --------------------------------------------------------------------------

def _decision(hit_dict: dict) -> dict:
    return {
        "action": hit_dict["final_action"],
        "seq": hit_dict["matched_seq"],
        "terminal": hit_dict["terminal"],           # rule | default
    }


def compute_impact(old_snap: dbmod.Snapshot, new_snap: dbmod.Snapshot,
                   rib: dbmod.RibSnapshot) -> dict:
    """Classify every reachable RIB prefix against both policy snapshots."""
    oldp = engine_policy_from_snapshot(old_snap)
    newp = engine_policy_from_snapshot(new_snap)
    if oldp.family != newp.family:
        raise PolicyError("policy snapshots belong to different families")
    family = oldp.family

    # Full-space semantic proof stays first-class (not sampled, not replaced).
    witnesses = [w.to_dict() for w in oldp.witness_diff(newp)]

    routes = [r for r in rib.routes if r.family == family]  # strict isolation

    rows: List[dict] = []
    sets: Dict[str, List[str]] = {
        "permitted_new": [], "denied_new": [], "unmatched_new": [],
        "permitted_old": [], "denied_old": [], "unmatched_old": [],
        "action_changed": [], "newly_permitted": [], "newly_denied": [],
        "decision_changed": [], "stable": [],
    }
    counts = {"hit_old": 0, "hit_new": 0,
              "unmatched_old": 0, "unmatched_new": 0}

    for r in routes:
        old_hit = oldp.classify(r.prefix).to_dict()
        new_hit = newp.classify(r.prefix).to_dict()
        d_old, d_new = _decision(old_hit), _decision(new_hit)
        changed_action = d_old["action"] != d_new["action"]
        changed_decision = (
            d_old["seq"] != d_new["seq"]
            or d_old["terminal"] != d_new["terminal"]
        )
        if changed_action:
            kind = ("newly_permitted"
                    if d_new["action"] == "permit" else "newly_denied")
            sets[kind].append(r.prefix)
            sets["action_changed"].append(r.prefix)
        if changed_decision:
            sets["decision_changed"].append(r.prefix)
        if not changed_decision and not changed_action:
            sets["stable"].append(r.prefix)

        for hit, side in ((old_hit, "old"), (new_hit, "new")):
            dec = _decision(hit)
            counts[f"hit_{side}"] += 1
            if dec["terminal"] == "default":
                counts[f"unmatched_{side}"] += 1
                sets[f"unmatched_{side}"].append(r.prefix)
            else:
                sets[f"{'permitted' if dec['action'] == 'permit' else 'denied'}_{side}"].append(
                    r.prefix)

        rows.append({
            "prefix": r.prefix, "family": family, "nexthop": r.nexthop,
            "old": {"chain": old_hit["chain"], **d_old},
            "new": {"chain": new_hit["chain"], **d_new},
            "action_changed": changed_action,
            "decision_changed": changed_decision,
        })

    rows.sort(key=lambda x: x["prefix"])
    for k in sets:
        sets[k] = sorted(set(sets[k]))

    summary = {
        "family": family,
        "route_count": len(routes),
        "permitted_new": len(sets["permitted_new"]),
        "denied_new": len(sets["denied_new"]),
        "unmatched_new": counts["unmatched_new"],
        "permitted_old": len(sets["permitted_old"]),
        "denied_old": len(sets["denied_old"]),
        "unmatched_old": counts["unmatched_old"],
        "action_changed": len(sets["action_changed"]),
        "newly_permitted": len(sets["newly_permitted"]),
        "newly_denied": len(sets["newly_denied"]),
        "decision_changed": len(sets["decision_changed"]),
        "stable": len(sets["stable"]),
        # full-space semantic proof (independent of the RIB)
        "full_space_witnesses": len(witnesses),
    }

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "family": family,
        "inputs": {
            "old_snapshot_id": old_snap.id,
            "old_version": old_snap.version,
            "new_snapshot_id": new_snap.id,
            "new_version": new_snap.version,
            "rib_snapshot_id": rib.id,
            "rib_content_hash": rib.content_hash,
            "rib_collected_at": rib.collected_at.isoformat()
            if rib.collected_at else None,
            "rib_source": rib.source,
            "rib_source_version": rib.source_version,
        },
        "summary": summary,
        "sets": sets,
        "routes": rows,
        "witnesses": witnesses,   # full-space minimal witness set (existing
                                  # semantic analysis, preserved verbatim)
    }


# --------------------------------------------------------------------------
# Serialization / export
# --------------------------------------------------------------------------

def task_dict(task: dbmod.ImpactTask, with_routes: bool = True,
              evidence: Optional[List[dbmod.ImpactEvidence]] = None) -> dict:
    out = {
        "id": task.id,
        "old_snapshot_id": task.old_snapshot_id,
        "new_snapshot_id": task.new_snapshot_id,
        "rib_snapshot_id": task.rib_snapshot_id,
        "input_digest": task.input_digest,
        "status": task.status,
        "attempts": task.attempts,
        "error": task.error,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "updated_at": task.updated_at.isoformat() if task.updated_at else None,
    }
    result = task.result
    if result and not with_routes:
        result = {k: v for k, v in result.items() if k != "routes"}
    out["result"] = result
    if evidence is not None:
        out["evidence"] = [_evidence_dict(e) for e in evidence]
    return out


def _evidence_dict(e: dbmod.ImpactEvidence) -> dict:
    return {
        "id": e.id, "task_id": e.task_id, "snapshot_id": e.snapshot_id,
        "node": e.node, "status": e.status, "sample_size": e.sample_size,
        "detail": e.detail, "created_at": e.created_at.isoformat()
        if e.created_at else None,
    }


def export_text(task: dbmod.ImpactTask) -> str:
    """Deterministic, replayable text export of one finished task."""
    if task.status != "succeeded" or not task.result:
        raise ValidationError("task has no successful result to export")
    r = task.result
    lines: List[str] = []
    lines.append("# impact-analysis export")
    lines.append(f"task_id={task.id}")
    lines.append(f"input_digest={task.input_digest}")
    inp = r["inputs"]
    lines.append(
        f"old=snapshot:{inp['old_snapshot_id']} v{inp['old_version']}")
    lines.append(
        f"new=snapshot:{inp['new_snapshot_id']} v{inp['new_version']}")
    lines.append(
        f"rib={inp['rib_snapshot_id']} hash={inp['rib_content_hash']} "
        f"collected_at={inp['rib_collected_at']} "
        f"source={inp['rib_source']!r} version={inp['rib_source_version']!r}")
    s = r["summary"]
    lines.append(
        f"summary routes={s['route_count']} family=IPv{s['family']} "
        f"permit_old={s['permitted_old']} deny_old={s['denied_old']} "
        f"unmatched_old={s['unmatched_old']} "
        f"permit_new={s['permitted_new']} deny_new={s['denied_new']} "
        f"unmatched_new={s['unmatched_new']} "
        f"action_changed={s['action_changed']} "
        f"(newly_permitted={s['newly_permitted']},"
        f"newly_denied={s['newly_denied']}) "
        f"decision_changed={s['decision_changed']} stable={s['stable']}")
    lines.append(f"full_space_witnesses={s['full_space_witnesses']}")
    for name in ("newly_permitted", "newly_denied", "action_changed",
                 "decision_changed", "unmatched_new"):
        lines.append(f"## {name}")
        lines.extend(r["sets"].get(name, []))
    lines.append("## routes: prefix old_action(old_seq) -> "
                 "new_action(new_seq) nexthop")
    for row in r["routes"]:
        o, n = row["old"], row["new"]
        mark = ("~" if row["action_changed"]
                else ("." if row["decision_changed"] else " "))
        lines.append(
            f"{mark} {row['prefix']} {o['action']}({o['seq'] or 'default'})"
            f" -> {n['action']}({n['seq'] or 'default'}) nh={row['nexthop']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# FRR container cross-validation of a LIMITED sample
# --------------------------------------------------------------------------

def cross_validate_sample(session: Session, task_id: int,
                          node: str = "a",
                          sample_size: int = 20,
                          bridge=None) -> dbmod.ImpactEvidence:
    """
    Push both policy snapshots' prefix-lists to a local FRR container and
    check a LIMITED, deterministic sample of the RIB (spread across the
    changed/stable/unmatched sets).  This is corroborating evidence only;
    the full analysis remains the ipaddress enumeration over every route.

    `bridge` may be injected (tests/fakes); otherwise a docker/ssh bridge
    to the local FRR lab is opened and closed here.
    """
    from .frr_bridge import FRRBridge
    from .validate import cross_validate as frr_cross_validate

    task = session.get(dbmod.ImpactTask, task_id)
    if task is None:
        raise ValidationError("task not found")
    if task.status != "succeeded":
        raise ValidationError("task must succeed before cross-validation")

    # re-verify pinning even at evidence-gathering time
    _load_bound_inputs(session, task)
    result = task.result
    sample = _sample_prefixes(result, sample_size)

    old = session.get(dbmod.Snapshot, task.old_snapshot_id)
    new = session.get(dbmod.Snapshot, task.new_snapshot_id)
    oldp = engine_policy_from_snapshot(old)
    newp = engine_policy_from_snapshot(new)

    owns_bridge = bridge is None
    if owns_bridge:
        bridge = FRRBridge(node=node).connect()
    try:
        ev_old = frr_cross_validate(oldp, sample, node=node, bridge=bridge,
                                    remove_after=False)
        ev_new = frr_cross_validate(newp, sample, node=node, bridge=bridge)
    finally:
        if owns_bridge:
            bridge.close()

    detail = {
        "sample": sample,
        "old": {"status": ev_old["status"],
                "mismatch_count": ev_old["mismatch_count"],
                "mismatches": ev_old["mismatches"]},
        "new": {"status": ev_new["status"],
                "mismatch_count": ev_new["mismatch_count"],
                "mismatches": ev_new["mismatches"]},
    }
    status = ("mismatch"
              if ev_old["mismatch_count"] or ev_new["mismatch_count"]
              else "match")
    ev = dbmod.ImpactEvidence(
        task_id=task.id, snapshot_id=task.new_snapshot_id, node=node,
        status=status, sample_size=len(sample), detail=detail)
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _sample_prefixes(result: dict, n: int) -> List[str]:
    """Deterministic, strata-balanced LIMITED sample — never the proof."""
    if n <= 0:
        return []
    strata = [
        result["sets"].get("newly_permitted", []),
        result["sets"].get("newly_denied", []),
        result["sets"].get("decision_changed", []),
        result["sets"].get("unmatched_new", []),
        result["sets"].get("stable", []),
    ]
    out: List[str] = []
    # round-robin one prefix per stratum until the budget is used
    pos = 0
    while len(out) < n:
        progressed = False
        for group in strata:
            if pos < len(group):
                pfx = group[pos]
                if pfx not in out:
                    out.append(pfx)
                    progressed = True
                if len(out) >= n:
                    break
        pos += 1
        if not progressed:
            break
    return out[:n]
