"""
RIB snapshot import + impact analysis — acceptance coverage:

* same policy change against two different RIBs -> different actual impact
* duplicate import does not duplicate routes (idempotent re-import +
  within-batch dedupe)
* IPv4/IPv6 strict isolation (route lines, next-hops, task binding)
* policy or RIB updates after analysis never rewrite a done result
* one illegal line fails the whole batch (nothing persisted)
* failed tasks are retryable; a simulated restart marks interrupted tasks,
  retry reproduces identical results, and provenance + FRR container
  evidence stay replayable
* a late-arriving old RIB is stored as a historical version only
"""
import pytest

from app import db as dbmod, impact


# ------------------------------------------------------------------ helpers

def _mk_policy(client, name, rules, default="deny", family=4):
    r = client.post("/api/policies", json={
        "name": name, "family": family, "default_action": default})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    if rules:
        r = client.put(f"/api/policies/{pid}/rules", json={"rules": rules})
        assert r.status_code == 200, r.text
    return pid


def _snap(client, pid, label):
    r = client.post(f"/api/policies/{pid}/snapshots", json={"label": label})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _mk_neighbor(client, name, ip="10.255.9.1", family=4):
    r = client.post("/api/neighbors", json={
        "name": name, "ip": ip, "family": family, "asn": 64999})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _import(client, routes, neighbor, family=4,
            collected="2026-09-24T08:00:00Z", src="collector#1"):
    return client.post("/api/ribs/import", json={
        "neighbor": neighbor, "family": family, "collected_at": collected,
        "source_version": src, "routes": routes})


def _run_task(client, rib_id, old_id, new_id):
    r = client.post("/api/impact/tasks", json={
        "rib_snapshot_id": rib_id, "old_snapshot_id": old_id,
        "new_snapshot_id": new_id})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------- import

def test_import_dedup_and_idempotent_reimport(client):
    _mk_neighbor(client, "rib-dup-nb")
    routes = [
        "10.1.0.0/16 10.255.9.1",
        "10.2.0.0/16 10.255.9.1",
        "10.1.0.0/16 10.255.9.1",          # exact duplicate line
        {"prefix": "10.3.0.0/16", "next_hop": "10.255.9.2"},
    ]
    r = _import(client, routes, "rib-dup-nb")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["created"] is True
    assert body["route_count"] == 3               # duplicate collapsed
    assert body["duplicates_collapsed"] == 1
    assert body["status"] == "frozen"
    rid = body["id"]

    # identical re-import -> same snapshot, no new routes
    r2 = _import(client, routes, "rib-dup-nb")
    assert r2.status_code == 200, r2.text
    assert r2.json()["deduplicated"] is True
    assert r2.json()["id"] == rid

    detail = client.get(f"/api/ribs/{rid}").json()
    assert detail["route_count"] == 3
    keys = [(x["prefix"], x["next_hop"]) for x in detail["routes"]]
    assert len(keys) == len(set(keys))            # no duplicate routes
    # ordinals keep first-occurrence line numbers (0-based)
    assert [x["ordinal"] for x in detail["routes"]] == [0, 1, 3]

    # same collection identity, DIFFERENT content -> conflict
    r3 = _import(client, ["10.9.0.0/16 10.255.9.1"], "rib-dup-nb")
    assert r3.status_code == 409


def test_illegal_line_fails_whole_batch(client):
    _mk_neighbor(client, "rib-bad-nb")
    before = len(client.get("/api/ribs").json())

    r = _import(client, [
        "10.1.0.0/16 10.255.9.1",          # good
        "not-a-prefix 10.255.9.1",         # illegal
        "10.2.0.0/16 10.255.9.1",          # good
    ], "rib-bad-nb")
    assert r.status_code == 422
    assert "line 2" in r.json()["detail"]

    # host bits set is not a network -> illegal
    r2 = _import(client, ["10.0.0.1/24 10.255.9.1"], "rib-bad-nb",
                 src="collector#2")
    assert r2.status_code == 422

    # bad next-hop
    r3 = _import(client, ["10.0.0.0/24 999.1.1.1"], "rib-bad-nb",
                 src="collector#3")
    assert r3.status_code == 422

    # nothing persisted: the whole batch was rejected atomically
    after = client.get("/api/ribs").json()
    assert len(after) == before
    assert all(x["neighbor"] != "rib-bad-nb" for x in after)


def test_family_isolation(client):
    _mk_neighbor(client, "rib-fam-nb", ip="10.255.9.2", family=4)
    _mk_neighbor(client, "rib-fam-nb6", ip="2001:db8:ffff::9", family=6)

    # v6 route inside a v4 import
    r = _import(client, ["2001:db8::/32 10.255.9.2"], "rib-fam-nb")
    assert r.status_code == 422 and "families" in r.json()["detail"]
    # v4 next-hop for a v6 route
    r = _import(client, ["2001:db8::/32 10.255.9.2"], "rib-fam-nb6",
                family=6, src="fam#1")
    assert r.status_code == 422 and "families" in r.json()["detail"]

    # a valid v6 RIB + v6 policy works end to end
    r = _import(client, ["2001:db8:1::/48 2001:db8:ffff::9",
                         "2001:db8:2::/48 2001:db8:ffff::9"],
                "rib-fam-nb6", family=6, src="fam#2")
    assert r.status_code == 201, r.text
    rib6 = r.json()["id"]

    p6 = _mk_policy(client, "fam-v6-pol", [
        {"seq": 10, "prefix": "2001:db8:1::/48", "action": "deny"},
        {"seq": 20, "prefix": "2001:db8::/32", "action": "permit", "le": 48},
    ], family=6)
    s6 = _snap(client, p6, "v6-only")
    t = _run_task(client, rib6, s6, s6)
    assert t["status"] == "done"
    assert t["result"]["summary"]["total"] == 2

    # v4 RIB x v6 policy snapshot -> rejected at binding time
    r = _import(client, ["10.1.0.0/16 10.255.9.2"], "rib-fam-nb", src="fam#3")
    rib4 = r.json()["id"]
    r = client.post("/api/impact/tasks", json={
        "rib_snapshot_id": rib4, "old_snapshot_id": s6, "new_snapshot_id": s6})
    assert r.status_code == 422 and "family" in r.json()["detail"]


def test_late_rib_is_historical_only(client):
    _mk_neighbor(client, "rib-late-nb")
    r1 = _import(client, ["10.1.0.0/16 10.255.9.1"], "rib-late-nb",
                 collected="2026-09-25T08:00:00Z", src="late#new")
    assert r1.json()["is_latest"] is True

    # an older collection arriving late: stored, but only as history
    r2 = _import(client, ["10.2.0.0/16 10.255.9.1"], "rib-late-nb",
                 collected="2026-09-20T08:00:00Z", src="late#old")
    assert r2.status_code == 201
    assert r2.json()["is_latest"] is False
    assert "historical" in r2.json()["warning"]

    ribs = {x["id"]: x for x in client.get("/api/ribs").json()}
    assert ribs[r1.json()["id"]]["is_latest"] is True
    assert ribs[r2.json()["id"]]["is_latest"] is False


# ------------------------------------------------------------------ impact

def _over_permit_pair(client, name):
    pid = _mk_policy(client, name, [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 24},
    ])
    old_id = _snap(client, pid, "before")
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"},
        {"seq": 20, "prefix": "192.168.0.0/16", "action": "permit", "le": 23},
        {"seq": 30, "prefix": "192.168.100.0/24", "action": "deny"},
    ]})
    new_id = _snap(client, pid, "after")
    return pid, old_id, new_id


def test_same_policy_two_ribs_different_impact(client):
    _mk_neighbor(client, "rib-imp-nb")
    _pid, old_id, new_id = _over_permit_pair(client, "imp-pol")

    # RIB X: nothing the policy change touches (/23 stays permitted, the
    # 10/16 route falls to default deny under both snapshots)
    rx = _import(client, ["192.168.200.0/23 10.255.9.1",
                          "10.1.0.0/16 10.255.9.1"], "rib-imp-nb",
                 src="imp#x").json()
    # RIB Y: carries the DC /24 that the tightened policy now denies
    ry = _import(client, ["192.168.100.0/24 10.255.9.1",
                          "192.168.200.0/23 10.255.9.1"], "rib-imp-nb",
                 collected="2026-09-25T08:00:00Z", src="imp#y").json()

    tx = _run_task(client, rx["id"], old_id, new_id)
    ty = _run_task(client, ry["id"], old_id, new_id)
    assert tx["status"] == ty["status"] == "done"

    sx, sy = tx["result"]["summary"], ty["result"]["summary"]
    assert sx["changed"] == 0                       # no actual impact on RIB X
    assert sy["changed"] == 1 and sy["newly_denied"] == 1
    changed_row = [r for r in ty["result"]["rows"] if r["changed"]][0]
    assert changed_row["prefix"] == "192.168.100.0/24"
    assert changed_row["old"]["action"] == "permit"
    assert changed_row["new"]["action"] == "deny"
    assert changed_row["new"]["seq"] == 30
    # per-route hit chains are stored for the UI / export
    assert changed_row["old_chain"] and changed_row["new_chain"]

    # the full-space semantic proof is identical for both tasks (it does not
    # depend on the RIB) — the RIB sample never replaces the proof
    px = tx["result"]["semantic_proof"]
    py = ty["result"]["semantic_proof"]
    assert px["witness_count"] == py["witness_count"] > 0
    assert [w["prefix"] for w in px["witnesses"]] == \
           [w["prefix"] for w in py["witnesses"]]

    # unmatched vs matched accounting is per-RIB
    assert sx["new"]["matched"] + sx["new"]["unmatched"] == sx["total"]


def test_updates_do_not_rewrite_results(client):
    _mk_neighbor(client, "rib-immut-nb")
    pid, old_id, new_id = _over_permit_pair(client, "immut-pol")
    rib = _import(client, ["192.168.100.0/24 10.255.9.1"], "rib-immut-nb",
                  src="immut#1").json()

    t = _run_task(client, rib["id"], old_id, new_id)
    assert t["status"] == "done"
    r1 = client.get(f"/api/impact/tasks/{t['id']}").json()["result"]
    assert r1 is not None

    # drift AFTER the analysis: edit the policy, snapshot again, import a
    # newer RIB — none of this may touch the finished task
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        {"seq": 10, "prefix": "0.0.0.0/0", "action": "permit", "le": 32},
    ]})
    _snap(client, pid, "v3")
    _import(client, ["192.168.100.0/24 10.255.9.1",
                     "203.0.113.0/24 10.255.9.1"], "rib-immut-nb",
            collected="2026-09-26T08:00:00Z", src="immut#2")

    r2 = client.get(f"/api/impact/tasks/{t['id']}").json()["result"]
    assert r2 == r1                                 # byte-identical result

    # re-posting the same input triple returns the same task, still R1
    again = _run_task(client, rib["id"], old_id, new_id)
    assert again["id"] == t["id"]
    assert again["result"] == r1

    # a done task cannot be re-run
    rr = client.post(f"/api/impact/tasks/{t['id']}/retry")
    assert rr.status_code == 409


def test_policy_delete_blocked_when_bound(client):
    _mk_neighbor(client, "rib-del-nb")
    pid, old_id, new_id = _over_permit_pair(client, "del-pol")
    rib = _import(client, ["10.1.0.0/16 10.255.9.1"], "rib-del-nb",
                  src="del#1").json()
    t = _run_task(client, rib["id"], old_id, new_id)
    assert t["status"] == "done"

    r = client.delete(f"/api/policies/{pid}")
    assert r.status_code == 409

    free = _mk_policy(client, "del-free", [])
    assert client.delete(f"/api/policies/{free}").status_code == 204


# ------------------------------------------------------- retry and restart

def test_failed_task_retry_and_restart_recovery(client, monkeypatch):
    _mk_neighbor(client, "rib-retry-nb")
    _pid, old_id, new_id = _over_permit_pair(client, "retry-pol")
    rib = _import(client, ["192.168.100.0/24 10.255.9.1"], "rib-retry-nb",
                  src="retry#1").json()

    # 1) force a compute failure -> task ends up failed, error persisted
    def boom(*a, **kw):
        raise RuntimeError("simulated compute crash")
    monkeypatch.setattr(impact, "compute_impact", boom)
    t = _run_task(client, rib["id"], old_id, new_id)
    assert t["status"] == "failed"
    assert "simulated compute crash" in t["error"]
    assert t["result"] is None
    monkeypatch.undo()

    # 2) retry succeeds; inputs are immutable so the result is deterministic
    r = client.post(f"/api/impact/tasks/{t['id']}/retry")
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["status"] == "done" and t["attempts"] == 2
    result_v1 = t["result"]
    assert result_v1["summary"]["changed"] == 1

    # 3) simulate a crash mid-run, then a service restart
    s = dbmod.SessionLocal()
    row = s.get(dbmod.ImpactTask, t["id"])
    row.status = "running"
    row.error = None
    s.commit()
    s.close()
    assert dbmod.recover_interrupted_tasks() == 1

    # a brand-new session (post-restart) still sees provenance + can retry
    t2 = client.get(f"/api/impact/tasks/{t['id']}").json()
    assert t2["status"] == "failed"
    assert "restart" in t2["error"]
    assert t2["inputs"]["rib"]["source_version"] == "retry#1"
    assert t2["input_fingerprint"] == t["input_fingerprint"]

    t3 = client.post(f"/api/impact/tasks/{t['id']}/retry").json()
    assert t3["status"] == "done"
    assert t3["result"] == result_v1                # identical replay
    assert t3["result"]["inputs"]["rib"]["source_version"] == "retry#1"


# ------------------------------------------------------- FRR cross-validation

class _FakeFRRBridge:
    """Minimal FRR behavior port for impact sampling (see
    tests/test_frr_consistency.py for the full version)."""
    def __init__(self):
        self.installed = {}

    def install_policy(self, policy, vrf=""):
        self.installed[policy.name] = policy
        return ""

    def remove_policy(self, name, family, vrf=""):
        self.installed.pop(name, None)
        return ""

    def show_prefix_list(self, name, family):
        p = self.installed[name]
        lines = [f"ip prefix-list {name}: {len(p.rules)} entries"]
        for r in p.rules:
            tail = ""
            if r.ge is not None:
                tail += f" ge {r.ge}"
            if r.le is not None:
                tail += f" le {r.le}"
            lines.append(f"   seq {r.seq} {r.action.value} {r.prefix}{tail}")
        return "\n".join(lines)

    def observe(self, name, family, prefix, vrf=""):
        from app.frr_bridge import FRRObservation
        hit = self.installed[name].classify(prefix)
        action = hit.final_action.value
        seq = hit.rule.seq if hit.rule else None
        raw = (f"ip prefix list {name} yields {action.upper()} for {prefix}, "
               + (f"matching entry #{seq}" if seq is not None else "no match found"))
        return FRRObservation(prefix, action, seq, raw)


def test_impact_cross_validate_with_frr_model(client):
    _mk_neighbor(client, "rib-cv-nb")
    _pid, old_id, new_id = _over_permit_pair(client, "cv-pol")
    rib = _import(client, ["192.168.100.0/24 10.255.9.1",
                           "192.168.200.0/24 10.255.9.1",
                           "10.1.0.0/16 10.255.9.1"], "rib-cv-nb",
                  src="cv#1").json()
    t = _run_task(client, rib["id"], old_id, new_id)

    s = dbmod.SessionLocal()
    try:
        out = impact.cross_validate_impact(s, t["id"], limit=2,
                                           bridge=_FakeFRRBridge())
    finally:
        s.close()
    assert out["status"] == "match", out.get("mismatches")
    assert out["impact_task_id"] == t["id"]
    # changed-first sampling: the one changed route must be sampled first
    assert out["sample"][0]["changed"] is True
    assert out["sample"][0]["prefix"] == "192.168.100.0/24"

    # container evidence persisted and linked to the task (replayable)
    runs = client.get(f"/api/impact/tasks/{t['id']}/runs").json()
    assert len(runs) == 1
    assert runs[0]["id"] == out["run_id"]
    assert runs[0]["status"] == "match"
    assert runs[0]["detail"]["impact_task_id"] == t["id"]
    assert runs[0]["detail"]["sample_strategy"] == "changed-first"

    # export carries the evidence as well
    exp = client.get(f"/api/impact/tasks/{t['id']}/export").json()
    assert exp["frr_runs"][0]["id"] == out["run_id"]


def test_impact_cross_validate_frr_unavailable(client, monkeypatch):
    _mk_neighbor(client, "rib-cv503-nb")
    _pid, old_id, new_id = _over_permit_pair(client, "cv503-pol")
    rib = _import(client, ["10.1.0.0/16 10.255.9.1"], "rib-cv503-nb",
                  src="cv503#1").json()
    t = _run_task(client, rib["id"], old_id, new_id)

    from app.frr_bridge import FRRUnavailable
    monkeypatch.setattr(impact, "cross_validate",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            FRRUnavailable("container down")))
    r = client.post(f"/api/impact/tasks/{t['id']}/cross-validate", json={})
    assert r.status_code == 503


# -------------------------------------------------------------------- export

def test_export_json_csv_and_rib_roundtrip(client):
    _mk_neighbor(client, "rib-exp-nb")
    _pid, old_id, new_id = _over_permit_pair(client, "exp-pol")
    rib = _import(client, ["192.168.100.0/24 10.255.9.1",
                           "10.1.0.0/16 10.255.9.1"], "rib-exp-nb",
                  src="exp#1").json()
    t = _run_task(client, rib["id"], old_id, new_id)

    # JSON export: self-contained (inputs + provenance + rows + proof)
    exp = client.get(f"/api/impact/tasks/{t['id']}/export").json()
    assert exp["export_kind"] == "rib-impact-analysis/v1"
    assert exp["inputs"]["rib"]["source_version"] == "exp#1"
    assert exp["inputs"]["rib"]["content_hash"] == rib["content_hash"]
    assert len(exp["result"]["rows"]) == 2
    assert exp["result"]["semantic_proof"]["witness_count"] > 0
    assert exp["input_fingerprint"] == t["input_fingerprint"]

    # CSV export: one line per route + header
    r = client.get(f"/api/impact/tasks/{t['id']}/export?format=csv")
    assert r.headers["content-type"].startswith("text/csv")
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("ordinal,prefix,next_hop")
    assert len(lines) == 3
    assert "192.168.100.0/24" in lines[1] or "192.168.100.0/24" in lines[2]

    # RIB export is re-importable (idempotent round-trip)
    rexp = client.get(f"/api/ribs/{rib['id']}/export").json()
    assert rexp["export_kind"] == "rib-snapshot/v1"
    routes = [f"{x['prefix']} {x['next_hop']}" for x in rexp["routes"]]
    r2 = _import(client, routes, "rib-exp-nb", src="exp#1")
    assert r2.status_code == 200 and r2.json()["deduplicated"] is True
