"""
Offline RIB snapshot import — never connects to a router.

An import describes a captured RIB at one point in time:

    neighbor, family, collected_at, source, source_version
    routes: [(prefix, nexthop), ...]

Two input shapes are accepted:

1. structured  -- the JSON API posts already-split route objects;
2. text        -- a captured table (one route per line), e.g. BGP style

       *> 192.168.1.0/24   10.0.0.1   0 64512 64600 ?
          2001:db8:1::/48   2001:db8:ffff::2 0 64512 i
       192.168.2.0/24 10.0.0.2

   Tokens that are valid as network + address become a route; anything else
   makes the WHOLE batch illegal (no partial imports).

Guarantees
----------
* STRICT, not sampled: every line is parsed through ``ipaddress``; host
  bits, malformed prefixes/nexthops and cross-family rows are illegal.
* v4/v6 isolation: one snapshot holds exactly one family; a v6 prefix with
  a v4 nexthop (or vice versa) rejects the batch.
* Deduplication: identical (prefix, nexthop) rows collapse to one route,
  both inside a batch and across imports (same content hash returns the
  already-frozen snapshot instead of duplicating routes).
* Atomic freeze: ALL rows validate before any DB write; snapshot + routes
  commit in one transaction and are only readable once ``frozen`` is set.
* A late RIB (older ``collected_at`` than the newest snapshot for the same
  neighbor/family) is kept as a HISTORICAL version (``stale=True``); it can
  never overwrite or replace a newer frozen snapshot.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
from dataclasses import dataclass
from typing import List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as dbmod


class RibImportError(ValueError):
    """Illegal import content; the whole batch must be rejected."""


@dataclass(frozen=True)
class ParsedRoute:
    prefix: str          # canonical
    family: int
    nexthop: str         # canonical
    raw: str

    def line(self) -> str:
        return f"{self.prefix} {self.nexthop}"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _parse_collected_at(value: str | dt.datetime) -> dt.datetime:
    if isinstance(value, dt.datetime):
        ts = value
    else:
        txt = str(value).strip()
        try:
            ts = dt.datetime.fromisoformat(txt.replace("Z", "+00:00"))
        except ValueError as e:
            raise RibImportError(f"bad collected_at {txt!r}: {e}") from e
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc).replace(tzinfo=None)


def parse_route_line(line: str, family: int, lineno: Optional[int] = None,
                     prefix_hint: Optional[str] = None,
                     nexthop_hint: Optional[str] = None) -> ParsedRoute:
    """
    Validate one route. Structured rows pass explicit hints; free-text lines
    are tokenized and must contain exactly one network and one address.
    """
    where = f"line {lineno}: " if lineno is not None else ""

    if prefix_hint is not None:
        tokens_ok = True
        try:
            net = ipaddress.ip_network(str(prefix_hint).strip(), strict=True)
            nh = ipaddress.ip_address(str(nexthop_hint).strip())
        except ValueError as e:
            raise RibImportError(f"{where}{line!r}: {e}") from e
        raw = line.strip() or f"{prefix_hint} {nexthop_hint}"
    else:
        raw = line.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith(("!", "#", "%")):
            raise RibImportError(f"{where}empty/comment rows are not allowed "
                                 "in a numbered import")
        nets, addrs = [], []
        for tok in stripped.replace(",", " ").split():
            # A RIB prefix is ALWAYS written with an explicit mask length
            # (10.0.0.0/24); requiring "/" keeps a bare nexthop address like
            # "10.0.0.1" from being misread as a /32 network.
            if "/" in tok:
                try:
                    nets.append(ipaddress.ip_network(tok, strict=True))
                    continue
                except ValueError:
                    pass
            try:
                addrs.append(ipaddress.ip_address(tok))
            except ValueError:
                pass  # path codes, AS numbers, flags ...
        if len(nets) != 1:
            raise RibImportError(
                f"{where}{raw!r}: expected exactly one prefix, found "
                f"{len(nets)}")
        if len(addrs) < 1:
            raise RibImportError(f"{where}{raw!r}: no valid nexthop address")
        net, nh, tokens_ok = nets[0], addrs[0], True

    if not tokens_ok:
        raise RibImportError(f"{where}{raw!r}: unparseable tokens")
    if net.version != family:
        raise RibImportError(
            f"{where}{raw!r}: prefix is IPv{net.version} but snapshot is "
            f"IPv{family} — families must not be mixed")
    if nh.version != family:
        raise RibImportError(
            f"{where}{raw!r}: nexthop {nh} is IPv{nh.version} but prefix is "
            f"IPv{family} — families must not be mixed")
    return ParsedRoute(prefix=str(net), family=family,
                       nexthop=str(nh), raw=raw)


def parse_routes(family: int,
                 structured: Optional[List[dict]] = None,
                 raw_text: Optional[str] = None) -> List[ParsedRoute]:
    """Parse and dedupe ALL routes before anything is persisted."""
    if family not in (4, 6):
        raise RibImportError(f"family must be 4 or 6, got {family}")
    parsed: List[ParsedRoute] = []
    if structured is not None:
        for i, row in enumerate(structured, start=1):
            parsed.append(parse_route_line(
                f"{row.get('prefix', '')} {row.get('nexthop', '')}",
                family, lineno=i,
                prefix_hint=row.get("prefix"),
                nexthop_hint=row.get("nexthop", "")))
    if raw_text:
        for i, line in enumerate(raw_text.splitlines(), start=1):
            if not line.strip() or line.strip().startswith(("!", "#", "%")):
                continue
            parsed.append(parse_route_line(line, family, lineno=i))
    if not parsed:
        raise RibImportError("RIB import contains zero valid routes")
    return dedupe(parsed)


def dedupe(routes: List[ParsedRoute]) -> List[ParsedRoute]:
    seen: set[Tuple[str, str]] = set()
    out: List[ParsedRoute] = []
    for r in routes:
        key = (r.prefix, r.nexthop)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def content_hash(family: int, routes: List[ParsedRoute],
                 neighbor: str, source: str) -> str:
    """
    Hash of the EXACT canonical route set (ordered, so it is stable) plus
    scope (family/neighbor/source). Two imports with the same routes hash to
    the same snapshot and never duplicate rows.
    """
    h = hashlib.sha256()
    h.update(f"{family}|{neighbor.strip().lower()}|{source.strip()}\n"
             .encode())
    for r in sorted(routes, key=lambda x: (x.prefix, x.nexthop)):
        h.update(r.line().encode() + b"\n")
    return h.hexdigest()


# --------------------------------------------------------------------------
# Import / persistence (atomic freeze)
# --------------------------------------------------------------------------

def import_snapshot(session: Session, *, name: str, neighbor: str, family: int,
                    collected_at: str | dt.datetime,
                    source: str = "", source_version: str = "",
                    routes: Optional[List[dict]] = None,
                    raw_text: Optional[str] = None) -> dbmod.RibSnapshot:
    """
    Validate the complete batch, then freeze snapshot+routes atomically.

    Everything parse/validation related happens BEFORE a single flush; on
    error the caller's transaction carries nothing (and the API route rolls
    back), so an illegal row can never leave a half-imported snapshot.
    """
    parsed = parse_routes(family, structured=routes, raw_text=raw_text)
    when = _parse_collected_at(collected_at)
    digest = content_hash(family, parsed, neighbor, source)

    existing = session.scalar(
        select(dbmod.RibSnapshot).where(
            dbmod.RibSnapshot.content_hash == digest))
    if existing is not None:
        # identical capture re-imported: no duplicate routes, no new version
        return existing

    newest = session.scalar(
        select(dbmod.RibSnapshot)
        .where(dbmod.RibSnapshot.neighbor == neighbor,
               dbmod.RibSnapshot.family == family)
        .order_by(dbmod.RibSnapshot.collected_at.desc(),
                  dbmod.RibSnapshot.id.desc()))
    stale = bool(newest is not None and when < newest.collected_at)

    snap = dbmod.RibSnapshot(
        name=name, neighbor=neighbor, family=family, collected_at=when,
        source=source, source_version=source_version,
        content_hash=digest, route_count=len(parsed), stale=stale,
        frozen=False,
        # exact imported evidence, retained so the import can be replayed
        raw_import="\n".join(r.raw for r in parsed),
    )
    session.add(snap)
    session.flush()                       # snap.id, still inside the txn
    session.add_all([
        dbmod.RibRoute(rib_id=snap.id, prefix=r.prefix, family=r.family,
                       nexthop=r.nexthop, raw=r.raw)
        for r in parsed
    ])
    snap.frozen = True                    # visible only after commit below
    try:
        session.commit()
    except Exception:
        session.rollback()
        raise
    session.refresh(snap)
    return snap


def rib_snapshot_dict(snap: dbmod.RibSnapshot,
                      with_routes: bool = False,
                      limit: Optional[int] = None) -> dict:
    d = {
        "id": snap.id,
        "name": snap.name,
        "neighbor": snap.neighbor,
        "family": snap.family,
        "collected_at": snap.collected_at.isoformat() if snap.collected_at
        else None,
        "source": snap.source,
        "source_version": snap.source_version,
        "content_hash": snap.content_hash,
        "route_count": snap.route_count,
        "stale": snap.stale,
        "frozen": snap.frozen,
        "created_at": snap.created_at.isoformat() if snap.created_at else None,
    }
    if with_routes:
        rs = snap.routes
        d["routes"] = [
            {"id": r.id, "prefix": r.prefix, "family": r.family,
             "nexthop": r.nexthop, "raw": r.raw}
            for r in (rs[:limit] if limit else rs)
        ]
        d["truncated"] = bool(limit and len(rs) > limit)
    return d


def load_routes(session: Session, rib_id: int) -> List[dbmod.RibRoute]:
    """Routes of a FROZEN snapshot only; an unfrozen row is never readable."""
    snap = session.get(dbmod.RibSnapshot, rib_id)
    if snap is None or not snap.frozen:
        raise RibImportError(f"RIB snapshot {rib_id} not found or not frozen")
    return list(snap.routes)
