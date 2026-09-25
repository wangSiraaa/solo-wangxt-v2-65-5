"""
RIB snapshot parsing + RIB-constrained impact analysis (pure logic, no DB).

A RIB snapshot is a frozen list of routes ``(prefix, next_hop)`` collected
offline from one neighbor and one address family.  Import rules:

* every line must parse (``ipaddress``, strict network form) and match the
  declared family — ONE illegal line fails the WHOLE batch (nothing is
  persisted);
* duplicate ``(prefix, next_hop)`` pairs collapse to a single route, keeping
  the first occurrence's line number as its ordinal;
* the route set is hashed (sha256) so re-imports are idempotent and impact
  tasks can pin their exact input.

``compute_impact`` answers the review question "which REAL routes does this
policy change actually touch?": every RIB route is classified against both
policy snapshots, yielding the actual hit / permitted / denied / unmatched /
changed sets.  The result ALSO carries the full-space minimal witness set
(exact semantic proof) — the RIB is a real-world sample, never a substitute
for the proof.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import List, Sequence, Tuple, Union

from .engine import Policy

MAX_ROUTES = 50000


class RibImportError(ValueError):
    """One or more RIB lines are illegal; the whole batch is rejected."""


@dataclass(frozen=True)
class RibEntry:
    ordinal: int            # line number (0-based) of first occurrence
    prefix: str             # canonical network, e.g. "192.168.100.0/24"
    next_hop: str


def parse_rib_routes(family: int,
                     raw_routes: Sequence[Union[str, dict]],
                     ) -> Tuple[List[RibEntry], int]:
    """
    Validate + dedupe one RIB batch.

    Accepts "PREFIX NEXT_HOP" strings or {"prefix": ..., "next_hop": ...}
    dicts.  Returns (entries, collapsed_duplicates).  Raises RibImportError
    listing every offending line if ANY line is illegal.
    """
    if family not in (4, 6):
        raise RibImportError(f"family must be 4 or 6, got {family!r}")
    if len(raw_routes) > MAX_ROUTES:
        raise RibImportError(
            f"too many routes ({len(raw_routes)} > {MAX_ROUTES}); "
            "split the collection into per-neighbor snapshots")

    errors: List[str] = []
    entries: List[RibEntry] = []
    seen: set = set()
    collapsed = 0

    for i, raw in enumerate(raw_routes):
        lineno = i + 1
        if isinstance(raw, str):
            parts = raw.replace(",", " ").split()
            if len(parts) != 2:
                errors.append(
                    f"line {lineno}: expected '<prefix> <next-hop>', got {raw!r}")
                continue
            pfx, nh = parts
        else:
            pfx = str(raw.get("prefix", "")).strip()
            nh = str(raw.get("next_hop", raw.get("nexthop", ""))).strip()
        try:
            net = ipaddress.ip_network(pfx, strict=True)
        except ValueError as e:
            errors.append(f"line {lineno}: bad prefix {pfx!r}: {e}")
            continue
        if net.version != family:
            errors.append(
                f"line {lineno}: {pfx} is IPv{net.version} but this RIB is "
                f"IPv{family}; address families must not be mixed")
            continue
        try:
            addr = ipaddress.ip_address(nh)
        except ValueError as e:
            errors.append(f"line {lineno}: bad next-hop {nh!r}: {e}")
            continue
        if addr.version != family:
            errors.append(
                f"line {lineno}: next-hop {nh} is IPv{addr.version} but this "
                f"RIB is IPv{family}; address families must not be mixed")
            continue
        key = (str(net), str(addr))
        if key in seen:
            collapsed += 1
            continue
        seen.add(key)
        entries.append(RibEntry(ordinal=i, prefix=key[0], next_hop=key[1]))

    if errors:
        head = "; ".join(errors[:20])
        if len(errors) > 20:
            head += f"; … and {len(errors) - 20} more"
        raise RibImportError(f"{len(errors)} illegal line(s): {head}")
    if not entries:
        raise RibImportError(
            "no routes: a RIB snapshot must contain at least one route")
    return entries, collapsed


def _canon_routes(entries: Sequence[RibEntry]) -> List[str]:
    def key(e: RibEntry):
        net = ipaddress.ip_network(e.prefix)
        return (int(net.network_address), net.prefixlen, e.next_hop)
    return [f"{e.prefix} {e.next_hop}" for e in sorted(entries, key=key)]


def rib_content_hash(entries: Sequence[RibEntry]) -> str:
    """Stable sha256 over the canonical (sorted) route set."""
    canon = "\n".join(_canon_routes(entries))
    return hashlib.sha256(canon.encode()).hexdigest()


def payload_hash(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def task_fingerprint(rib_hash: str, old_payload: dict, new_payload: dict) -> str:
    """Pin a task to its complete input: RIB content + both policy snapshots."""
    return hashlib.sha256(json.dumps({
        "rib": rib_hash,
        "old_policy": payload_hash(old_payload),
        "new_policy": payload_hash(new_payload),
    }, sort_keys=True).encode()).hexdigest()


def compute_impact(entries: Sequence[RibEntry],
                   old_policy: Policy,
                   new_policy: Policy) -> dict:
    """
    Classify every RIB route against both policy snapshots.

    Per route: old/new final action, matched seq (or default fall-through)
    and the full hit chain for each side.  Summary splits the RIB into the
    actual-hit / permitted / denied / unmatched / changed sets.  The
    full-space minimal witness diff is attached as the semantic proof.
    """
    summary = {
        "total": 0,
        "old": {"permit": 0, "deny": 0, "matched": 0, "unmatched": 0},
        "new": {"permit": 0, "deny": 0, "matched": 0, "unmatched": 0},
        "changed": 0, "newly_permitted": 0, "newly_denied": 0,
    }
    rows = []
    for e in entries:
        ho = old_policy.classify(e.prefix)
        hn = new_policy.classify(e.prefix)
        hod, hnd = ho.to_dict(), hn.to_dict()
        changed = ho.final_action != hn.final_action
        summary["total"] += 1
        for side, h in (("old", ho), ("new", hn)):
            summary[side][h.final_action.value] += 1
            summary[side]["matched" if h.terminal == "rule" else "unmatched"] += 1
        if changed:
            summary["changed"] += 1
            key = ("newly_permitted" if hn.final_action.value == "permit"
                   else "newly_denied")
            summary[key] += 1
        rows.append({
            "ordinal": e.ordinal,
            "prefix": e.prefix,
            "next_hop": e.next_hop,
            "old": {"action": hod["final_action"], "seq": hod["matched_seq"],
                    "terminal": hod["terminal"]},
            "new": {"action": hnd["final_action"], "seq": hnd["matched_seq"],
                    "terminal": hnd["terminal"]},
            "changed": changed,
            "old_chain": hod["chain"],
            "new_chain": hnd["chain"],
        })

    witnesses = [w.to_dict() for w in old_policy.witness_diff(new_policy)]
    return {
        "summary": summary,
        "rows": rows,
        "semantic_proof": {
            "kind": "full-space minimal witness set (exact enumeration, "
                    "not sampled from the RIB)",
            "witness_count": len(witnesses),
            "witnesses": witnesses,
        },
    }
