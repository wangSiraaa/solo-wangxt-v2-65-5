"""
Seed the workbench with the three required worked scenarios.

1. OVER-PERMIT  : a too-wide le range admits an internal /24 range intended
                  only as aggregates.
2. REORDER      : two overlapping rules swap seq; the narrower deny is
                  shadowed after the swap.
3. DEFAULT-FLIP : removing the catch-all permit flips the implicit action.

Each scenario stores two snapshots (before/after) plus an ordered probe
list, so it is fully replayable.

Offline RIB captures are seeded too (nothing connects to a router):

* two DIFFERENT RIB snapshots for the over-permit neighbor, so the same
  before/after policy pair demonstrably has a different ACTUAL impact on
  the reachable prefixes each RIB hands the policy;
* one IPv6 RIB for over-permit-v6 (strict family isolation);
* one LATE capture (older collected_at) kept purely as a historical version.
"""
from __future__ import annotations

from . import db as dbmod, impact, rib, service


SEEDS = {
    4: {
        "over-permit": {
            "description": "le 24 lets DC more-specifics through (should be le 23)",
            "before": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
                    {"seq": 20, "prefix": "192.168.0.0/16",
                     "action": "permit", "le": 24},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
                    {"seq": 20, "prefix": "192.168.0.0/16",
                     "action": "permit", "le": 23},
                    # explicit guard: /24 services must stay denied
                    {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"},
                ],
            },
            "probes": [
                "192.168.0.0/16",
                "192.168.100.0/24",
                "192.168.100.128/25",
                "192.168.200.0/24",
                "192.168.200.0/23",
                "10.1.2.3/32",
                "8.8.8.8/32",
            ],
        },
        "reorder": {
            "description": "broad permit moved BEFORE narrow deny (swap seq)",
            "before": {
                "default_action": "deny",
                "rules": [
                    # narrower deny at seq 10 wins first inside 172.31/16
                    {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
                    {"seq": 20, "prefix": "172.16.0.0/12",
                     "action": "permit", "le": 32},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    # same two lines, but broad permit now at seq 5:
                    # first-match -> 172.31/16 deny is fully shadowed
                    {"seq": 5, "prefix": "172.16.0.0/12",
                     "action": "permit", "le": 32},
                    {"seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
                ],
            },
            "probes": [
                "172.16.0.0/12",
                "172.20.1.0/24",
                "172.31.0.0/16",
                "172.31.5.0/24",
                "172.32.0.0/16",
            ],
        },
        "default-flip": {
            "description": "catch-all permit removed: implicit default -> deny",
            "before": {
                "default_action": "permit",
                "rules": [
                    {"seq": 10, "prefix": "203.0.113.0/24",
                     "action": "deny"},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "203.0.113.0/24",
                     "action": "deny"},
                    {"seq": 20, "prefix": "198.51.100.0/24",
                     "action": "permit"},
                ],
            },
            "probes": [
                "203.0.113.0/24",
                "203.0.113.7/32",
                "198.51.100.0/24",
                "192.0.2.1/32",
                "104.16.0.0/12",
            ],
        },
    },
    6: {
        "over-permit-v6": {
            "description": "le 48 admits site /48s intended to stay internal",
            "before": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "2001:db8:1::/48", "action": "deny"},
                    {"seq": 20, "prefix": "2001:db8::/32",
                     "action": "permit", "le": 48},
                ],
            },
            "after": {
                "default_action": "deny",
                "rules": [
                    {"seq": 10, "prefix": "2001:db8:1::/48", "action": "deny"},
                    {"seq": 20, "prefix": "2001:db8::/32",
                     "action": "permit", "le": 40},
                ],
            },
            "probes": [
                "2001:db8::/32",
                "2001:db8::/40",
                "2001:db8:1::/48",
                "2001:db8:2::/48",
                "2001:db8:1:1::/64",
                "2001:dead::/32",
            ],
        },
    },
}

NEIGHBORS = [
    dict(name="edge-r1", ip="10.255.0.1", family=4, asn=64512,
         inbound_policy="over-permit",
         description="local edge, FRR router-a"),
    dict(name="core-r2", ip="10.255.0.2", family=4, asn=64513,
         inbound_policy="reorder",
         description="local core, FRR router-b"),
    dict(name="edge-v6-r1", ip="2001:db8:ffff::1", family=6, asn=64512,
         inbound_policy="over-permit-v6",
         description="local edge IPv6, FRR router-a"),
]


# Offline RIB captures (neighbor, family, collected_at, source/version,
# routes). Two IPv4 RIBs for the SAME neighbor at different times hold
# different reachable prefix sets, so the over-permit before/after policy
# pair has a genuinely different ACTUAL impact on each.  The third entry is
# LATE (older than the newest capture for that neighbor) and is retained
# only as a historical version (stale=True).
RIBS = [
    dict(
        name="edge-r1 RIB 2026-09-20 morning", neighbor="edge-r1", family=4,
        collected_at="2026-09-20T08:00:00+00:00",
        source="show ip bgp export", source_version="FRR 8.4.1",
        routes=[
            ("192.168.100.0/24", "10.255.0.1"),   # permit -> deny
            ("192.168.200.0/24", "10.255.0.1"),   # permit -> deny
            ("192.168.200.0/23", "10.255.0.1"),   # permit -> permit
            ("10.0.0.0/8", "10.255.0.254"),       # deny -> deny (seq 10)
            ("8.8.8.8/32", "10.255.0.254"),       # default deny, unmatched
        ],
    ),
    dict(
        name="edge-r1 RIB 2026-09-20 evening", neighbor="edge-r1", family=4,
        collected_at="2026-09-20T20:00:00+00:00",
        source="show ip bgp export", source_version="FRR 8.4.1",
        routes=[
            ("192.168.0.0/24", "10.255.0.1"),     # permit -> deny
            ("192.168.50.0/24", "10.255.0.1"),    # permit -> deny
            ("192.168.100.128/25", "10.255.0.1"),  # permit -> default deny
            ("10.0.0.0/8", "10.255.0.254"),       # deny -> deny (seq 10)
            ("203.0.113.0/24", "10.255.0.254"),   # default deny, unmatched
        ],
    ),
    dict(
        name="edge-v6-r1 RIB 2026-09-20", neighbor="edge-v6-r1", family=6,
        collected_at="2026-09-20T08:30:00+00:00",
        source="show ipv6 bgp export", source_version="FRR 8.4.1",
        routes=[
            ("2001:db8:1::/48", "2001:db8:ffff::254"),   # deny -> deny
            ("2001:db8:2::/48", "2001:db8:ffff::1"),     # permit -> deny
            ("2001:db8::/40", "2001:db8:ffff::1"),       # permit -> permit
            ("2001:db8:dead::/64", "2001:db8:ffff::1"),  # default deny
            ("2001:dead::/32", "2001:db8:ffff::254"),    # default deny
        ],
    ),
    dict(
        # arrives/imported LAST but is OLDER -> historical version only
        name="edge-r1 RIB 2026-09-19 (late import)", neighbor="edge-r1",
        family=4, collected_at="2026-09-19T23:00:00+00:00",
        source="show ip bgp export", source_version="FRR 8.4.1",
        routes=[
            ("192.168.100.0/24", "10.255.0.1"),
            ("192.168.201.0/24", "10.255.0.1"),
            ("10.1.2.3/32", "10.255.0.254"),
        ],
    ),
]


def seed_all() -> None:
    dbmod.init_db()
    s = dbmod.SessionLocal()
    try:
        for nb in NEIGHBORS:
            if not s.query(dbmod.Neighbor).filter_by(name=nb["name"]).first():
                s.add(dbmod.Neighbor(**nb))

        snapshot_ids = {}
        for family, scenarios in SEEDS.items():
            for slug, spec in scenarios.items():
                pname = slug
                dbp = s.query(dbmod.Policy).filter_by(name=pname).first()
                if dbp is None:
                    dbp = dbmod.Policy(
                        name=pname, family=family,
                        default_action=spec["before"]["default_action"],
                        description=spec["description"], draft=False)
                    s.add(dbp)
                    s.commit()
                    service.replace_rules(s, dbp, spec["before"]["rules"])
                    snap_before = service.create_snapshot(s, dbp, label="before")

                    dbp.default_action = spec["after"]["default_action"]
                    s.commit()
                    service.replace_rules(s, dbp, spec["after"]["rules"])
                    snap_after = service.create_snapshot(s, dbp, label="after")

                    sc = dbmod.Scenario(
                        name=pname, description=spec["description"],
                        from_snapshot_id=snap_before.id,
                        to_snapshot_id=snap_after.id,
                        probes=spec["probes"],
                    )
                    s.add(sc)
                    s.commit()
                else:
                    snaps = (s.query(dbmod.Snapshot)
                             .filter_by(policy_id=dbp.id)
                             .order_by(dbmod.Snapshot.version).all())
                    snap_before, snap_after = snaps[0], snaps[-1]
                snapshot_ids[pname] = (snap_before.id, snap_after.id)

        # Offline RIB snapshots (idempotent: identical content reuses the
        # frozen row).  Order matters for the stale-history check: the late
        # capture is imported after the newer ones.
        rib_ids = {}
        for spec in RIBS:
            existing = (s.query(dbmod.RibSnapshot)
                        .filter_by(name=spec["name"]).first())
            if existing is None:
                rsnap = rib.import_snapshot(
                    s, name=spec["name"], neighbor=spec["neighbor"],
                    family=spec["family"], collected_at=spec["collected_at"],
                    source=spec["source"], source_version=spec["source_version"],
                    routes=[{"prefix": p, "nexthop": nh}
                            for p, nh in spec["routes"]])
            else:
                rsnap = existing
            rib_ids[spec["name"]] = rsnap

        # Pre-bind impact analyses so the workbench opens with real
        # same-policy/two-RIB, different-actual-impact evidence.
        def _ensure_task(old_id, new_id, rsnap):
            have = s.query(dbmod.ImpactTask).filter_by(
                old_snapshot_id=old_id, new_snapshot_id=new_id,
                rib_snapshot_id=rsnap.id).first()
            if have is None:
                impact.create_task(
                    s, old_snapshot_id=old_id, new_snapshot_id=new_id,
                    rib_snapshot_id=rsnap.id, run=True)

        b_id, a_id = snapshot_ids["over-permit"]
        _ensure_task(b_id, a_id, rib_ids["edge-r1 RIB 2026-09-20 morning"])
        _ensure_task(b_id, a_id, rib_ids["edge-r1 RIB 2026-09-20 evening"])
        b6, a6 = snapshot_ids["over-permit-v6"]
        _ensure_task(b6, a6, rib_ids["edge-v6-r1 RIB 2026-09-20"])
    finally:
        s.close()


if __name__ == "__main__":
    seed_all()
    print("seed complete")
