"""
Acceptance tests for RIB snapshot import + impact analysis.

Covers the required acceptance set:
  * the SAME policy pair against TWO RIBs yields DIFFERENT actual impact;
  * a repeated import never duplicates routes (in-batch + cross-batch);
  * strict IPv4/IPv6 isolation at import and analysis time;
  * policy / RIB updates DURING analysis cannot rewrite a bound result;
  * one illegal row fails the WHOLE batch atomically;
  * after (simulated) restart + retry the result, source and FRR evidence
    remain replayable;
  * RIB impact supplements but never replaces the full-space witness proof;
  * a late (older) RIB is stored only as a historical version.
"""
import datetime as dt

import pytest

from app import db as dbmod, impact, rib
from app.engine import policy_from_dicts


# ------------------------------------------------------------- test fixtures

def _policy_pair(client, name="acc-policy", family=4,
                 before_rules=None, after_rules=None):
    pid = client.post("/api/policies", json={
        "name": name, "family": family}).json()["id"]
    client.put(f"/api/policies/{pid}/rules",
               json={"rules": before_rules})
    old = client.post(f"/api/policies/{pid}/snapshots",
                      json={"label": "before"}).json()["id"]
    client.put(f"/api/policies/{pid}/rules",
               json={"rules": after_rules})
    new = client.post(f"/api/policies/{pid}/snapshots",
                      json={"label": "after"}).json()["id"]
    return pid, old, new


BEFORE = [
    {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
    {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
]
AFTER = [
    {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
    {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
    {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"},
]


def _import_rib(client, name, routes, family=4, when="2026-09-20T08:00:00+00:00",
                neighbor="edge", source="export", version="FRR 8.4.1",
                raw=False):
    body = {"name": name, "neighbor": neighbor, "family": family,
            "collected_at": when, "source": source, "source_version": version}
    if raw:
        body["raw_text"] = "\n".join(f"{p} {nh}" for p, nh in routes)
    else:
        body["routes"] = [{"prefix": p, "nexthop": nh} for p, nh in routes]
    return client.post("/api/ribs", json=body)


def _task(client, old, new, rid, run=True):
    return client.post("/api/impact/tasks", json={
        "old_snapshot_id": old, "new_snapshot_id": new,
        "rib_snapshot_id": rid, "run": run})


@pytest.fixture(autouse=True)
def _clean_rib_tables():
    # these API tests share the session-scoped client DB
    s = dbmod.SessionLocal()
    for tbl in (dbmod.ImpactEvidence, dbmod.ImpactTask, dbmod.RibRoute,
                dbmod.RibSnapshot):
        s.query(tbl).delete()
    s.commit()
    s.close()
    yield


# ------------------------------------------------------------------- cases

def test_same_policy_two_ribs_different_impact(client):
    pid, old, new = _policy_pair(client, before_rules=BEFORE, after_rules=AFTER)
    rib_a = _import_rib(client, "rib-A", [
        ("192.168.100.0/24", "10.0.0.1"),   # permit -> deny
        ("192.168.200.0/24", "10.0.0.1"),   # permit -> deny
        ("192.168.200.0/23", "10.0.0.1"),   # stays permitted
        ("8.8.8.8/32", "10.0.0.2"),         # default deny both sides
    ], when="2026-09-20T08:00:00+00:00").json()["id"]
    rib_b = _import_rib(client, "rib-B", [
        ("192.168.50.0/24", "10.0.0.1"),     # permit -> deny
        ("192.168.0.0/23", "10.0.0.1"),      # permitted on both sides
        ("10.0.0.0/8", "10.0.0.2"),          # deny -> deny (explicit rule)
    ], when="2026-09-20T20:00:00+00:00").json()["id"]

    ta = _task(client, old, new, rib_a).json()
    tb = _task(client, old, new, rib_b).json()
    sa, sb = ta["result"]["summary"], tb["result"]["summary"]

    assert sa["route_count"] == 4 and sb["route_count"] == 3
    # actual impact differs: RIB-A has TWO routes falling through to the
    # implicit default on the new side (200.0/24 + 8.8.8.8/32); RIB-B has
    # one (50.0/24 leaves the tightened window) and different permit/deny
    # counts, so the realized impact is not the same set at all
    assert sa["permitted_new"] == 1 and sb["permitted_new"] == 1
    assert sa["denied_new"] == 1 and sb["denied_new"] == 1
    assert sa["unmatched_new"] == 2 and sb["unmatched_new"] == 1
    assert sa["action_changed"] == 2 and sb["action_changed"] == 1
    # and the concrete changed-prefix sets are actually different
    changed_a = set(ta["result"]["sets"]["action_changed"])
    changed_b = set(tb["result"]["sets"]["action_changed"])
    assert changed_a != changed_b
    assert changed_a == {"192.168.100.0/24", "192.168.200.0/24"}
    assert changed_b == {"192.168.50.0/24"}


def test_duplicate_import_does_not_duplicate_routes(client):
    routes = [("192.168.1.0/24", "10.0.0.1"),
              ("192.168.1.0/24", "10.0.0.1"),          # dup within batch
              ("192.168.2.0/24", "10.0.0.2")]
    r1 = _import_rib(client, "dup", routes)
    assert r1.status_code == 201, r1.text
    assert r1.json()["route_count"] == 2

    # identical re-import (even via raw text) returns the SAME frozen row
    r2 = _import_rib(client, "dup", routes[:2] + [routes[2]], raw=True)
    assert r2.status_code == 201
    assert r2.json()["id"] == r1.json()["id"]
    s = dbmod.SessionLocal()
    try:
        assert s.query(dbmod.RibRoute).filter_by(rib_id=r1.json()["id"]).count() == 2
        assert s.query(dbmod.RibSnapshot).filter_by(name="dup").count() == 1
    finally:
        s.close()


def test_ipv4_ipv6_strict_isolation(client):
    # v6 prefix into a v4 snapshot -> whole batch rejected
    r = _import_rib(client, "mix1", [
        ("192.168.1.0/24", "10.0.0.1"),
        ("2001:db8::/48", "10.0.0.1"),
    ], family=4)
    assert r.status_code == 422 and "famil" in r.json()["detail"]

    # v6 nexthop with v4 prefix -> rejected
    r = _import_rib(client, "mix2", [
        ("192.168.1.0/24", "2001:db8::1"),
    ], family=4)
    assert r.status_code == 422

    # a legal v6 RIB works and can only be analyzed by a v6 policy pair
    pid4, old4, new4 = _policy_pair(client, "iso-v4",
                                    before_rules=BEFORE, after_rules=AFTER)
    rid6 = _import_rib(client, "iso-v6rib", [
        ("2001:db8::/48", "2001:db8:ffff::1"),
    ], family=6).json()["id"]
    r = _task(client, old4, new4, rid6)
    assert r.status_code == 422 and "famil" in r.json()["detail"]

    # v6 policy + v6 RIB: v4 prefixes can never appear in its routes
    pid6, old6, new6 = _policy_pair(
        client, name="iso-v6pol", family=6,
        before_rules=[{"seq": 10, "prefix": "2001:db8::/32",
                       "action": "permit", "le": 48}],
        after_rules=[{"seq": 10, "prefix": "2001:db8::/32",
                      "action": "permit", "le": 40}])
    out = _task(client, old6, new6, rid6).json()
    assert out["result"]["family"] == 6
    assert all(row["family"] == 6 for row in out["result"]["routes"])


def test_policy_update_during_analysis_does_not_rewrite_result(client):
    pid, old, new = _policy_pair(client, "freeze-policy",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "freeze-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
        ("192.168.200.0/24", "10.0.0.1"),
    ]).json()["id"]
    t = _task(client, old, new, rid).json()
    digest_before = t["input_digest"]
    changed_before = t["result"]["sets"]["action_changed"]

    # mutate the LIVE policy and take a fresh snapshot after the analysis
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "0.0.0.0/0", "action": "permit"},
    ]})
    client.post(f"/api/policies/{pid}/snapshots", json={"label": "v3"})

    # fetching the finished task returns the ORIGINAL, bound result
    again = client.get(f"/api/impact/tasks/{t['id']}").json()
    assert again["input_digest"] == digest_before
    assert again["result"]["sets"]["action_changed"] == changed_before
    assert again["result"]["inputs"]["new_version"] == 2
    # even tampering with a live policy row cannot move the frozen snapshot
    s = dbmod.SessionLocal()
    try:
        db_pol = s.query(dbmod.Policy).filter_by(name="freeze-policy").one()
        db_pol.default_action = "permit"
        s.commit()
    finally:
        s.close()
    still = client.get(f"/api/impact/tasks/{t['id']}").json()
    assert still["input_digest"] == digest_before
    assert still["status"] == "succeeded"


def test_rib_update_during_analysis_cannot_rewrite_result(client, monkeypatch):
    pid, old, new = _policy_pair(client, "freeze-rib-pol",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "freeze-rib2", [
        ("192.168.100.0/24", "10.0.0.1"),
    ]).json()["id"]

    # create task but run it ourselves, and simulate another RIB import
    # landing WHILE the computation is in flight (mid run_task)
    t0 = _task(client, old, new, rid, run=False).json()
    s = dbmod.SessionLocal()
    try:
        task = s.get(dbmod.ImpactTask, t0["id"])

        import app.impact as im
        orig = im.compute_impact

        def slow_compute(o, n, ribrow):
            # a newer, different RIB is imported concurrently; it must not
            # touch the frozen row this task is bound to
            other = dbmod.SessionLocal()
            try:
                rib.import_snapshot(
                    other, name="concurrent", neighbor="edge", family=4,
                    collected_at="2026-09-25T00:00:00+00:00",
                    source="export", routes=[
                        {"prefix": "172.16.0.0/12", "nexthop": "10.9.9.9"}])
            finally:
                other.close()
            return orig(o, n, ribrow)

        monkeypatch.setattr(im, "compute_impact", slow_compute)
        impact.run_task(s, task.id)
        s.refresh(task)
        assert task.status == "succeeded"
        # the bound RIB is unchanged and the result is about its routes only
        assert task.result["summary"]["route_count"] == 1
        assert task.result["routes"][0]["prefix"] == "192.168.100.0/24"
    finally:
        s.close()


def test_illegal_row_fails_whole_batch_and_leaves_nothing(client):
    r = _import_rib(client, "bad-batch", [
        ("192.168.1.0/24", "10.0.0.1"),
        ("not-a-prefix", "10.0.0.2"),
        ("192.168.3.0/24", "10.0.0.3"),
    ])
    assert r.status_code == 422
    assert "line 2" in r.json()["detail"]
    s = dbmod.SessionLocal()
    try:
        # tables started empty for this test and no valid import happened:
        # a failed batch leaves neither a snapshot nor any routes behind
        assert s.query(dbmod.RibSnapshot).count() == 0
        assert s.query(dbmod.RibRoute).count() == 0
    finally:
        s.close()

    # host bits set on the prefix are illegal too (strict parsing)
    r = _import_rib(client, "hostbits", [("192.168.1.7/24", "10.0.0.1")])
    assert r.status_code == 422

    # free-text: an unparseable junk line fails the entire text batch
    r = client.post("/api/ribs", json={
        "name": "bad-text", "neighbor": "edge", "family": 4,
        "collected_at": "2026-09-20T08:00:00+00:00",
        "raw_text": "*> 192.168.1.0/24 10.0.0.1 0 64512 i\n"
                    "garbage-line-without-any-address\n"})
    assert r.status_code == 422


def test_late_rib_is_history_only(client):
    newer = _import_rib(client, "newer", [("192.168.1.0/24", "10.0.0.1")],
                        when="2026-09-20T20:00:00+00:00", neighbor="edge")
    assert newer.json()["stale"] is False
    late = _import_rib(client, "late", [("192.168.9.0/24", "10.0.0.9")],
                       when="2026-09-10T20:00:00+00:00", neighbor="edge")
    assert late.status_code == 201
    assert late.json()["stale"] is True
    # the newer capture is untouched; list ordering keeps newest first
    ribs = client.get("/api/ribs").json()
    by_name = {r["name"]: r for r in ribs}
    assert by_name["newer"]["stale"] is False
    assert ribs[0]["collected_at"] >= ribs[-1]["collected_at"]


def test_full_space_witnesses_remain_beside_rib_impact(client):
    pid, old, new = _policy_pair(client, "proof",
                                 before_rules=BEFORE, after_rules=AFTER)
    # tiny RIB that does NOT itself exercise every behavior region
    rid = _import_rib(client, "proof-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
    ]).json()["id"]
    out = _task(client, old, new, rid).json()
    r = out["result"]
    assert r["summary"]["route_count"] == 1
    # the full-space semantic proof is still present and larger than the RIB
    assert r["summary"]["full_space_witnesses"] == len(r["witnesses"])
    assert r["summary"]["full_space_witnesses"] >= 2
    assert any(w["prefix"] != "192.168.100.0/24" for w in r["witnesses"])


def test_task_retry_after_failure_is_replayable(client, monkeypatch):
    pid, old, new = _policy_pair(client, "retry-pol",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "retry-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
        ("192.168.200.0/24", "10.0.0.1"),
    ]).json()["id"]
    t0 = _task(client, old, new, rid, run=False).json()

    # force the first attempt to fail
    import app.impact as im
    def boom(*a, **k):
        raise RuntimeError("simulated compute crash")
    monkeypatch.setattr(im, "compute_impact", boom)
    s = dbmod.SessionLocal()
    try:
        t = impact.run_task(s, t0["id"])
        assert t.status == "failed" and t.attempts == 1
        assert "simulated compute crash" in (t.error or "")
        monkeypatch.undo()
        t = impact.run_task(s, t0["id"])
        assert t.status == "succeeded" and t.attempts == 2
        changed = t.result["sets"]["action_changed"]
        digest = t.input_digest
    finally:
        s.close()

    # simulate restart: brand-new sessions/processes, DB already persisted
    s2 = dbmod.SessionLocal()
    try:
        t = s2.get(dbmod.ImpactTask, t0["id"])
        assert t.status == "succeeded"
        assert t.input_digest == digest
        assert t.result["sets"]["action_changed"] == changed
        ribrow = s2.get(dbmod.RibSnapshot, rid)
        assert ribrow.source == "export" and ribrow.source_version == "FRR 8.4.1"
        assert ribrow.frozen and t.result["inputs"]["rib_source"] == "export"
    finally:
        s2.close()

    # HTTP retry on an already-succeeded task is idempotent and same-version
    r = client.post(f"/api/impact/tasks/{t0['id']}/retry")
    assert r.status_code == 200
    assert r.json()["input_digest"] == digest


def test_export_is_deterministic_and_replayable(client):
    pid, old, new = _policy_pair(client, "export-pol",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "export-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
    ]).json()["id"]
    t = _task(client, old, new, rid).json()
    a = client.get(f"/api/impact/tasks/{t['id']}/export").text
    b = client.get(f"/api/impact/tasks/{t['id']}/export").text
    assert a == b
    assert f"input_digest={t['input_digest']}" in a
    assert "192.168.100.0/24" in a
    assert "full_space_witnesses=" in a


def test_rib_per_route_hit_chains_complete(client):
    pid, old, new = _policy_pair(client, "chains",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "chains-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
    ]).json()["id"]
    out = _task(client, old, new, rid).json()
    row = out["result"]["routes"][0]
    assert row["prefix"] == "192.168.100.0/24"
    assert row["old"]["action"] == "permit" and row["old"]["seq"] == 20
    assert row["new"]["action"] == "deny" and row["new"]["seq"] == 30
    assert row["action_changed"] is True
    # full hit chain per side: every rule evaluated + implicit default entry
    assert {e["seq"] for e in row["old"]["chain"] if e["seq"]} == {10, 20}
    assert {e["seq"] for e in row["new"]["chain"] if e["seq"]} == {10, 20, 30}


# ----------------------------------------------- FRR container cross-check

class _FakeFRR:
    """Minimal stand-in implementing FRR plist.c semantics (test oracle)."""
    import ipaddress as _ipa

    def __init__(self):
        self.installed = {}

    def install_policy(self, policy, vrf=""):
        self.installed[(policy.name, policy.family)] = policy
        return ""

    def remove_policy(self, name, family, vrf=""):
        self.installed.pop((name, family), None)
        return ""

    def show_prefix_list(self, name, family):
        p = self.installed[(name, family)]
        return "\n".join(f"seq {r.seq} {r.action.value}" for r in p.rules)

    def observe(self, name, family, prefix, vrf=""):
        from app.frr_bridge import FRRObservation
        p = self.installed[(name, family)]
        net = self._ipa.ip_network(prefix)
        best = None
        for r in p.rules:
            if r.family != family or not net.subnet_of(r.net):
                continue
            if r.ge is None and r.le is None:
                if net.prefixlen != r.net.prefixlen:
                    continue
            else:
                if r.le is not None and net.prefixlen > r.le:
                    continue
                if r.ge is not None and net.prefixlen < r.ge:
                    continue
            if best is None or r.seq < best.seq:
                best = r
        if best is None:
            return FRRObservation(prefix, "deny", None, "no match found")
        return FRRObservation(prefix, best.action.value, best.seq, "match")


def test_frr_sample_evidence_is_stored_and_replayable(client):
    pid, old, new = _policy_pair(client, "frr-pol",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "frr-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
        ("192.168.200.0/24", "10.0.0.1"),
        ("10.0.0.0/8", "10.0.0.2"),
        ("8.8.8.8/32", "10.0.0.2"),
    ]).json()["id"]
    t = _task(client, old, new, rid).json()

    s = dbmod.SessionLocal()
    try:
        ev = impact.cross_validate_sample(s, t["id"], node="a",
                                          sample_size=4, bridge=_FakeFRR())
        assert ev.status == "match" and ev.sample_size == 4
        # both snapshots checked, zero mismatches against the FRR model
        assert ev.detail["old"]["mismatch_count"] == 0
        assert ev.detail["new"]["mismatch_count"] == 0
        ev_id = ev.id
    finally:
        s.close()

    # evidence survives a "restart": re-read from a fresh session and via API
    s2 = dbmod.SessionLocal()
    try:
        again = s2.get(dbmod.ImpactEvidence, ev_id)
        assert again is not None and again.status == "match"
        assert set(again.detail["sample"]) == {
            "192.168.100.0/24", "192.168.200.0/24", "10.0.0.0/8", "8.8.8.8/32"}
    finally:
        s2.close()
    out = client.get(f"/api/impact/tasks/{t['id']}").json()
    assert out["evidence"] and out["evidence"][0]["status"] == "match"
    assert out["evidence"][0]["sample_size"] == 4


def test_live_frr_sample_when_container_present(client):
    """Runs only when a real local FRR container is actually reachable."""
    from app.frr_bridge import FRRBridge, FRRUnavailable
    try:
        FRRBridge(node="a", timeout=4).connect().close()
    except Exception:
        pytest.skip("FRR router-a container not reachable")
    pid, old, new = _policy_pair(client, "live-pol",
                                 before_rules=BEFORE, after_rules=AFTER)
    rid = _import_rib(client, "live-rib", [
        ("192.168.100.0/24", "10.0.0.1"),
        ("192.168.200.0/23", "10.0.0.1"),
        ("8.8.8.8/32", "10.0.0.2"),
    ]).json()["id"]
    t = _task(client, old, new, rid).json()
    r = client.post(f"/api/impact/tasks/{t['id']}/cross-validate",
                    json={"node": "a", "sample_size": 3})
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "match"

