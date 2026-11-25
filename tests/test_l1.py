"""L1 at scale: tokens, store, sync, views, freshness (offline, simulated core).
Run: pytest tests"""

import json
import os
import random
import re
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pytest  # noqa: E402
import yaml  # noqa: E402

from agent.tool_client import LocalToolClient  # noqa: E402
from gateway import build_l1_gateway  # noqa: E402
from gateway.l1 import (Free5GCSource, IdentifierTokenizer, SourceError, SyncEngine,  # noqa: E402
                        UEState, UEStateStore)
from gateway.policy import PolicyEngine  # noqa: E402
from sim import SimCore, serve  # noqa: E402

KEY = b"k" * 32
with open(os.path.join(ROOT, "config.yaml")) as f:
    L1 = yaml.safe_load(f)["l1"]
REL = "trigger_pdu_session_release"


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def stack(n=100, scope="s1", clock=None, wall=None, core=None, sync=None, **sync_kw):
    clock, wall = clock or Clock(), wall or Clock(3600 * 1000.0 + 600)
    core = core or SimCore(n)
    if sync is None:
        sync = SyncEngine(Free5GCSource(core.get), now_fn=clock,
                          **{"audit_per_cycle": 0, **sync_kw})
        assert sync.step()
    gw = build_l1_gateway(LocalToolClient(core.tools()), sync, L1, KEY, scope, now_fn=wall)
    return core, sync, gw, clock, wall


def all_ues(gw, **kw):
    out, page = [], ""
    while page is not None:
        r = gw.invoke("list_ues", {"page_token": page, **kw} if page else kw)
        out += r["ues"]
        page = r["next_page"]
    return out


def with_session(gw):
    return next(u for u in all_ues(gw) if u["sessions"])


def release(gw, u, **kw):
    args = {"supi_token": u["supi_token"], "pdu_session_id": 1, "if_etag": u["sessions"][0]["etag"]}
    return gw.invoke(REL, {**args, **kw})


# --- tokens ------------------------------------------------------------------ #
def test_tokens_do_not_depend_on_order_and_do_not_collide():
    supis = SimCore(10_000).supis
    a, b = IdentifierTokenizer(KEY), IdentifierTokenizer(KEY)
    ta = {s: a.token_for(s) for s in supis}
    random.Random(0).shuffle(supis)
    assert {s: b.token_for(s) for s in supis} == ta and len(set(ta.values())) == len(ta)


def test_peer_gateway_resolves_token_it_never_minted():
    core, sync, gw, _, wall = stack()
    tok = all_ues(gw)[0]["supi_token"]
    _, _, peer, _, _ = stack(core=core, sync=sync, wall=wall)
    assert peer.invoke("get_ue", {"supi_token": tok})["registered"] is True


def test_scopes_are_unlinkable_by_token_and_etag():
    core, sync, g1, _, wall = stack()
    _, _, g2, _, _ = stack(core=core, sync=sync, scope="s2", wall=wall)
    u1, u2 = all_ues(g1), all_ues(g2)
    keys = lambda us: {u["supi_token"] for u in us} | {s["etag"] for u in us for s in u["sessions"]}  # noqa: E731
    assert len(u1) == len(u2) and not keys(u1) & keys(u2)
    assert g2.invoke("get_ue", {"supi_token": u1[0]["supi_token"]})["violation"] == "unknown-token"


def test_rotation_and_grace():
    _, _, gw, _, wall = stack()
    tok = all_ues(gw)[0]["supi_token"]
    wall.t += 3600 - 600 + 60                     # next epoch, inside the 120 s grace
    assert gw.invoke("get_ue", {"supi_token": tok})["status"] == "ok"
    assert tok not in {u["supi_token"] for u in all_ues(gw)}
    wall.t += 120                                 # grace over
    assert gw.invoke("get_ue", {"supi_token": tok})["violation"] == "unknown-token"


def test_rotation_forces_resync_of_cursors_and_pages():
    _, _, gw, _, wall = stack()
    r = gw.invoke("list_ues", {"limit": 5})
    wall.t += 3600
    assert gw.invoke("get_changes", {"cursor": r["cursor"]})["resync_required"]
    assert gw.invoke("list_ues", {"page_token": r["next_page"]})["resync_required"]


def test_etag_accepted_in_grace():
    _, _, gw, _, wall = stack()
    u = with_session(gw)
    wall.t += 3600 - 600 + 60
    assert release(gw, u)["status"] == "ok"


def test_grace_longer_than_epoch_is_rejected():
    with pytest.raises(ValueError):
        IdentifierTokenizer(KEY, epoch_sec=10, grace_sec=11)


# --- what reaches the agent ---------------------------------------------------- #
def test_no_real_identifier_reaches_the_agent_in_any_view():
    core, sync, gw, _, _ = stack(1000)
    seen = [gw.invoke("get_network_summary", {}), all_ues(gw)]
    cur = seen[0]["cursor"]
    core.advance(0.5)
    sync.step()
    seen += [gw.invoke("get_changes", {"cursor": cur}),
             gw.invoke("get_ue", {"supi_token": all_ues(gw)[0]["supi_token"]}),
             release(gw, with_session(gw))]
    assert seen[2]["resync_required"] is False and seen[2]["updated"] and seen[4]["status"] == "ok"
    text = json.dumps(seen)
    assert not [i for i in core.real_identifiers() if i in text]
    assert "tac" not in json.dumps(seen[1]).lower()


def test_v1_tools_do_not_leak_other_identifiers_any_more():
    """v1 tokenized only the SUPI: list_subscribers handed out every phone number."""
    tk = IdentifierTokenizer(KEY)
    out = json.dumps(tk.tokenize({
        "ueId": "imsi-208930000000001", "gpsi": "msisdn-0900000001", "msisdn": "0900000077", "Guti": "20893cafe0000000001",
        "pei": "imei-356938035643809", "PDUAddress": "10.60.0.1", "smContextRef": "urn:uuid:" + "a" * 8,
        "detail": "no uesimtun iface bound to 10.61.0.9; core at 127.0.0.2",
        "imsi-208930000000002": 208930000000003}))
    for bad in ("0900000001", "0900000077", "cafe", "356938035643809", "10.60.0.1", "10.61.0.9", "aaaaaaaa",
                "208930000000002", "208930000000003"):
        assert bad not in out
    assert "127.0.0.2" in out


def test_raw_identifiers_in_nested_arguments_are_blocked():
    _, _, gw, _, _ = stack()
    for bad in ({"x": ["imsi-208930000000001"]}, {"imsi-208930000000001": 1}, "msisdn-0900000001",
                208930000000001):
        assert gw.invoke("get_alert_logs", {"log_id": bad})["violation"] == "raw-identifier"
    assert gw.invoke("get_ue", {"supi_token": ["x"]})["violation"] == "unknown-token"


def test_planted_supi_in_a_log_is_not_an_oracle():
    core, _, gw, _, _ = stack()
    core.alert = f"check {next(iter(core.ues))} and msisdn-0900000001"
    msg = gw.invoke("get_alert_logs", {"log_id": "a"})["log"]["message"]
    assert "token_sub_" not in msg and "2089300" not in msg and "0900000001" not in msg


def test_order_does_not_reveal_imsi_rank():
    core, _, gw, _, _ = stack(1000)
    tok = gw.tokenizer
    ranks = [core.supis.index(tok.resolve(u["supi_token"])) for u in all_ues(gw)]
    assert ranks != sorted(ranks)
    n = len(ranks)
    expected = sorted(ranks)
    pos = {r: i for i, r in enumerate(expected)}
    d2 = sum((i - pos[r]) ** 2 for i, r in enumerate(ranks))
    assert abs(1 - 6 * d2 / (n * (n * n - 1))) < 0.15      # Spearman rank correlation ~ 0


def test_moving_ue_does_not_show_up_as_a_change():
    core, sync, gw, _, _ = stack()
    cur = gw.invoke("get_network_summary", {})["cursor"]
    for ue in core.ues.values():
        ue["tac"] = "000009"
    sync.step()
    r = gw.invoke("get_changes", {"cursor": cur})
    assert r["updated"] == [] and r["removed"] == []
    assert gw.invoke("get_network_summary", {})["by_area"] == {"000009": len(core.ues)}


def test_small_areas_are_merged():
    core, sync, gw, _, _ = stack()
    for i, ue in enumerate(core.ues.values()):
        ue["tac"] = "000042" if i < 3 else "000001"
    sync.step()
    assert gw.invoke("get_network_summary", {})["by_area"] == {"000001": len(core.ues) - 3, "other": 3}


# --- bounded payloads ------------------------------------------------------------ #
def test_payloads_are_bounded_at_5000_ues():
    core, sync, gw, _, _ = stack(5000)
    assert len(gw.invoke("list_ues", {"limit": 10 ** 6})["ues"]) == 50
    assert len(json.dumps(gw.invoke("get_network_summary", {}))) < 1000
    assert len(all_ues(gw)) == len(core.ues)
    assert gw.invoke("list_subscribers", {})["status"] == "error"


def test_paging_is_stable_while_ues_come_and_go():
    core, sync, gw, _, _ = stack(500)
    stay, seen, page = set(core.ues), [], ""
    while page is not None:
        r = gw.invoke("list_ues", {"page_token": page} if page else {})
        seen += [gw.tokenizer.resolve(u["supi_token"]) for u in r["ues"]]
        page = r["next_page"]
        core.advance(1)
        sync.step()
        stay &= set(core.ues)
    assert len(seen) == len(set(seen)) and stay <= set(seen)


def test_delta_stream_converges_to_the_full_view():
    core, sync, gw, _, _ = stack(300)
    view = {u["supi_token"]: u for u in all_ues(gw)}
    cur = gw.invoke("get_network_summary", {})["cursor"]
    for _ in range(40):
        core.advance(1)
        sync.step()
        r = gw.invoke("get_changes", {"cursor": cur})
        assert not r["resync_required"]
        cur = r["cursor"]
        view.update({u["supi_token"]: u for u in r["updated"]})
        for t in r["removed"]:
            view.pop(t, None)
    assert view == {u["supi_token"]: u for u in all_ues(gw)}


def test_too_old_or_too_big_delta_asks_for_resync():
    core, sync, gw, _, _ = stack(1000)
    assert gw.invoke("get_changes", {"cursor": gw.invoke("list_ues", {})["cursor"].split(".")[0] + ".0"})["resync_required"]
    st = UEStateStore(max_tombstones=2)
    st.apply_snapshot({s: UEState(s) for s in "abcde"}, 1)
    v = st.version
    for i, gone in enumerate("abc"):
        st.apply_ue(gone, None, 2 + i)
    assert st.changes_since(v).resync and not st.changes_since(v + 1).resync


def test_bad_arguments_do_not_crash():
    _, _, gw, _, _ = stack()
    for name, args in (("get_changes", {"cursor": "x"}), ("get_changes", {}), ("list_ues", {"limit": "a"}),
                       ("get_ue", {}), ("list_ues", {"nope": 1})):
        assert gw.invoke(name, args)["status"] == "error"


# --- synchronization ------------------------------------------------------------- #
def test_failed_read_keeps_state_and_turns_stale():
    core, sync, gw, clock, _ = stack()
    n = len(sync.store)
    core.down = True
    clock.t += 10
    assert sync.step() is False and len(sync.store) == n
    r = gw.invoke("get_network_summary", {})
    assert r["stale"] is True and r["ues"] == n


def test_implausible_shrink_needs_confirmation_and_null_means_empty():
    core, sync, _, _, _ = stack()
    n = len(sync.store)
    core.ues.clear()                         # AMF restarted: answers `null`
    assert sync.step() is False and len(sync.store) == n
    assert sync.step() is True and len(sync.store) == 0


@pytest.mark.parametrize("code,body", [(404, {"cause": "No AMF Found"}), (200, {"x": 1}), (200, [1]),
                                       (200, [{"Supi": "imsi-1", "PduSessions": [{}]}])])
def test_unclear_answers_are_errors_not_empty(code, body):
    class R:
        status_code = code

        def json(self):
            return body
    src = Free5GCSource(lambda p: R())
    with pytest.raises(SourceError):
        src.snapshot()
    with pytest.raises(SourceError):
        src.read_ue("imsi-1")


def test_release_is_written_through_although_amf_stays_stale():
    core, sync, gw, _, _ = stack()
    u = with_session(gw)
    assert release(gw, u)["status"] == "ok"
    sync.step()                              # AMF still lists it
    assert core._ctx(gw.tokenizer.resolve(u["supi_token"]))["PduSessions"]
    assert gw.invoke("get_ue", {"supi_token": u["supi_token"]})["ue"]["sessions"] == []


def test_audit_finds_out_of_band_release_within_its_bound():
    core, sync, gw, _, _ = stack(100, audit_per_cycle=10)
    ref = next(iter(core.smf))
    supi = core.smf[ref][0]
    core.smf_release(ref)
    for _ in range(-(-len(core.ues) // 10) + 1):
        sync.step()
    assert sync.store.get(supi).state.sessions == ()


def test_old_snapshot_does_not_overwrite_newer_refresh():
    st = UEStateStore()
    old, new = UEState("u", "IDLE"), UEState("u", "CONNECTED")
    st.apply_snapshot({"u": old}, 1)
    st.apply_ue("u", new, 5)
    st.apply_snapshot({"u": old}, 4)
    assert st.get("u").state == new
    st.apply_ue("u", None, 6)
    st.apply_snapshot({"u": old}, 5.5)       # read before it left
    assert st.get("u") is None
    st.apply_snapshot({"u": old}, 7)
    assert st.get("u") is not None


def test_concurrent_agents_and_sync_stay_consistent():
    core = SimCore(1000)
    sync = SyncEngine(Free5GCSource(core.get), interval_sec=0.01, audit_per_cycle=5)
    sync.step()
    errors, stop = [], threading.Event()

    def agent(i):
        try:
            _, _, gw, _, _ = stack(core=core, sync=sync, scope=f"s{i}")
            real = set(core.real_identifiers())
            for _ in range(5):
                r = gw.invoke("list_ues", {})
                assert len(r["ues"]) == 50
                txt = json.dumps(r)
                assert not re.search(r"imsi-\d", txt) and not any(x in txt for x in list(real)[:200])
                assert gw.invoke("get_changes", {"cursor": r["cursor"]})["status"] == "ok"
        except Exception as e:               # noqa: BLE001
            errors.append(repr(e))

    def churn():
        while not stop.is_set():
            core.advance(0.1)
    sync.start()
    threads = [threading.Thread(target=agent, args=(i,)) for i in range(8)]
    c = threading.Thread(target=churn)
    c.start()
    [t.start() for t in threads]
    [t.join() for t in threads]
    stop.set()
    c.join()
    sync.stop()
    assert not errors and sync.stats["failed"] == 0
    sync.step()
    assert set(sync.store.supis()[1]) == set(core.ues)


def test_adapter_over_real_http():
    from free5gc_tools import core_state as cs
    core = SimCore(1000)
    srv, url = serve(core)
    old = dict(cs._CFG)
    try:
        cs.set_config({"free5gc": {"webconsole_url": url, "username": "a", "password": "b"}})
        sync = SyncEngine(Free5GCSource(), audit_per_cycle=0)
        assert sync.step() and len(sync.store) == len(core.ues) and core.requests == 1
        assert sync.source.read_ue("imsi-208939999999999") is None
    finally:
        cs.set_config(old)
        cs._wc_token = ""
        srv.shutdown()
        srv.server_close()


# --- freshness ------------------------------------------------------------------- #
def test_release_of_vanished_session_is_blocked():
    core, _, gw, clock, _ = stack()
    u = with_session(gw)
    core._deregister(gw.tokenizer.resolve(u["supi_token"]))
    clock.t += 5
    assert release(gw, u)["violation"] == "stale-target"


def test_session_released_at_smf_is_blocked_even_if_amf_lists_it():
    core, _, gw, clock, _ = stack()
    u = with_session(gw)
    core.smf_release(core.ues[gw.tokenizer.resolve(u["supi_token"])]["sess"][1][0])
    clock.t += 5
    assert release(gw, u)["violation"] == "stale-target"


def test_reestablished_session_under_same_id_is_not_hit():
    core, _, gw, clock, _ = stack()
    u = with_session(gw)
    supi = gw.tokenizer.resolve(u["supi_token"])
    core.smf_release(core.ues[supi]["sess"].pop(1)[0])
    core._up(supi, 1)
    clock.t += 5
    assert release(gw, u)["violation"] == "stale-view"
    assert core.ues[supi]["sess"][1][0] in core.smf


def test_change_between_check_and_release_is_not_hit():
    core, _, gw, _, _ = stack()
    u = with_session(gw)
    supi, inner = gw.tokenizer.resolve(u["supi_token"]), gw.inner.inner
    real = inner.invoke

    def racing(name, args):
        core.smf_release(core.ues[supi]["sess"].pop(1)[0])
        core._up(supi, 1)
        return real(name, args)
    inner.invoke = racing
    assert release(gw, u)["status"] == "noop"
    assert core.ues[supi]["sess"][1][0] in core.smf


def test_etag_required_and_agent_cannot_choose_the_ref():
    core, _, gw, _, _ = stack()
    u = with_session(gw)
    assert release(gw, u, if_etag=None)["violation"] == "stale-view"
    assert release(gw, u, if_etag="é")["violation"] == "stale-view"
    assert release(gw, u, expected_sm_context_ref="nonsense")["status"] == "ok"


def test_idle_connected_flapping_does_not_block():
    core, _, gw, clock, _ = stack()
    u = with_session(gw)
    ue = core.ues[gw.tokenizer.resolve(u["supi_token"])]
    ue["cm"] = "IDLE" if ue["cm"] == "CONNECTED" else "CONNECTED"
    clock.t += 5
    assert release(gw, u)["status"] == "ok"


def test_unreadable_core_blocks():
    core, _, gw, clock, _ = stack()
    u = with_session(gw)
    core.down = True
    clock.t += 5
    assert release(gw, u)["violation"] == "state-unverifiable"
    clock.t -= 5                              # record still fresh, SMF unreachable
    assert release(gw, u)["violation"] == "state-unverifiable"


def test_freshness_without_sync_is_rejected_at_build_time():
    with pytest.raises(ValueError):
        PolicyEngine(L1["policy"], IdentifierTokenizer(KEY))


def test_unlisted_tool_is_never_unchecked():
    pe = PolicyEngine({"tools": {}}, IdentifierTokenizer(KEY))
    assert [c.kind for c in pe.chains["*"]] == ["identifier"]


def test_tool_refuses_when_ref_changed(monkeypatch):
    """The live release tool itself, not the simulated one."""
    from free5gc_tools import core_state as cs, tools
    monkeypatch.setattr(cs, "amf_pdu_session", lambda s, p: {"id": 1, "sm_context_ref": "urn:uuid:new"})
    monkeypatch.setattr(cs, "smf_release_sm_context", lambda *a, **k: pytest.fail("reached the SMF"))
    r = tools.trigger_pdu_session_release("imsi-208930000000001", 1, expected_sm_context_ref="urn:uuid:old")
    assert r["status"] == "noop" and r["verified"] is False
