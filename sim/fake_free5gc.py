"""
sim/fake_free5gc.py — a free5GC-shaped core with N UEs and churn
================================================================
Reproduces what L1 depends on, with the shapes read from the vendored v4.1.0 source:
  * GET /api/registered-ue-context[/{supi}]  AMF OAM (array; `null` when empty;
    404 CONTEXT_NOT_FOUND for an unknown UE), in IMSI order
  * GET /api/ue-pdu-session-info/{ref}       SMF OAM (404 when unknown)
  * GET /api/subscriber, /api/subscriber/{supi}/{plmn}; POST /api/login
  * a release at the SMF leaves the AMF's entry stale

It does not model radio, NAS, NF load or signalling delay. Latency measured against it
is gateway + HTTP cost only.
"""

from __future__ import annotations

import json
import random
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple


class Resp:
    def __init__(self, code: int, body: Any):
        self.status_code, self._body, self.ok = code, body, 200 <= code < 300
        self.text = json.dumps(body)

    def json(self) -> Any:
        return json.loads(self.text)


class SimCore:
    DNNS = (("internet", "1", "010203"), ("ims", "1", "010203"), ("iot", "3", "112233"))
    # events per UE per second: attach/detach, session up/down, CM idle/connected, TA move
    RATES = {"reg": 0.002, "sess": 0.005, "cm": 0.02, "move": 0.005}

    def __init__(self, n: int, seed: int = 1, registered: float = 0.9):
        self.rng = random.Random(seed)
        self.lock = threading.RLock()
        self.supis = [f"imsi-20893{i:010d}" for i in range(1, n + 1)]
        self.gpsi = {s: f"msisdn-09{i:08d}" for i, s in enumerate(self.supis, 1)}
        self.ues: Dict[str, Dict[str, Any]] = {}
        self.smf: Dict[str, Tuple[str, int]] = {}     # ref -> (supi, psi): authoritative
        self.requests = self.bytes = self.events = 0
        self.down = False
        for s in self.supis:
            if self.rng.random() < registered:
                self._register(s)

    # -- dynamics -------------------------------------------------------------
    def _register(self, supi: str) -> None:
        self.ues[supi] = {"cm": self.rng.choice(["CONNECTED", "IDLE"]), "tac": f"{self.rng.randint(1, 8):06d}",
                          "guti": f"20893cafe{self.rng.getrandbits(40):010x}", "sess": {}}
        self._up(supi, 1)

    def _up(self, supi: str, psi: int) -> None:
        ref = uuid.UUID(int=self.rng.getrandbits(128)).urn
        self.ues[supi]["sess"][psi] = (ref,) + self.rng.choice(self.DNNS)
        self.smf[ref] = (supi, psi)

    def _deregister(self, supi: str) -> None:
        for ref, *_ in self.ues.pop(supi)["sess"].values():
            self.smf.pop(ref, None)

    def advance(self, dt: float) -> int:
        """Run dt seconds of churn; returns the number of events."""
        with self.lock:
            n = 0
            for kind, rate in self.RATES.items():
                lam = rate * dt * len(self.supis)
                k = int(lam) + (self.rng.random() < lam - int(lam))
                for s in self.rng.sample(self.supis, min(k, len(self.supis))):
                    n += 1
                    ue = self.ues.get(s)
                    if kind == "reg":
                        self._deregister(s) if ue else self._register(s)
                    elif ue is None:
                        n -= 1
                    elif kind == "sess":
                        if 1 in ue["sess"]:
                            self.smf.pop(ue["sess"].pop(1)[0], None)
                        else:
                            self._up(s, 1)
                    elif kind == "cm":
                        ue["cm"] = "IDLE" if ue["cm"] == "CONNECTED" else "CONNECTED"
                    else:
                        ue["tac"] = f"{self.rng.randint(1, 8):06d}"
            self.events += n
            return n

    def smf_release(self, ref: str) -> bool:
        """Direct SMF release: the AMF entry stays (stale), as on free5GC."""
        with self.lock:
            return self.smf.pop(ref, None) is not None

    def real_identifiers(self) -> List[str]:
        """Everything an agent must never see."""
        with self.lock:
            out = [s[5:] for s in self.supis] + [g[7:] for g in self.gpsi.values()]
            for ue in self.ues.values():
                out.append(ue["guti"])
                out += [r[0] for r in ue["sess"].values()]
            return out

    # -- REST -----------------------------------------------------------------
    def _ctx(self, supi: str) -> Dict[str, Any]:
        ue = self.ues[supi]
        return {"AccessType": "3GPP_ACCESS", "Supi": supi, "Guti": ue["guti"], "Mcc": "208", "Mnc": "93",
                "Tac": ue["tac"], "CmState": ue["cm"],
                "PduSessions": [{"PduSessionId": str(p), "SmContextRef": r, "Sst": sst, "Sd": sd, "Dnn": dnn}
                                for p, (r, dnn, sst, sd) in sorted(ue["sess"].items())] or None}

    def get(self, path: str) -> Resp:
        with self.lock:
            r = Resp(500, {"cause": "down"}) if self.down else self._route(path)
            self.requests += 1
            self.bytes += len(r.text)
            return r

    def _route(self, path: str) -> Resp:
        parts = path.strip("/").split("/")
        if parts[:2] == ["api", "registered-ue-context"]:
            if len(parts) == 2:
                return Resp(200, [self._ctx(s) for s in sorted(self.ues)] or None)
            if parts[2] in self.ues:
                return Resp(200, [self._ctx(parts[2])])
            return Resp(404, {"status": 404, "cause": "CONTEXT_NOT_FOUND"})
        if parts[:2] == ["api", "ue-pdu-session-info"]:
            if parts[2] in self.smf:
                supi, psi = self.smf[parts[2]]
                return Resp(200, {"Supi": supi, "PDUSessionID": str(psi), "PDUAddress": "10.60.0.7",
                                  "UpCnxState": "ACTIVATED"})
            return Resp(404, None)
        if parts == ["api", "subscriber"]:
            return Resp(200, [{"plmnID": "20893", "ueId": s, "gpsi": self.gpsi[s]} for s in self.supis])
        if parts[:2] == ["api", "subscriber"]:
            return Resp(200, {"ueId": parts[2], "AccessAndMobilitySubscriptionData": {}})
        return Resp(404, {"cause": "no such path"})

    # -- agent-side core tools (v1 shape), for a full gateway stack ----------------
    def tools(self) -> Dict[str, Any]:
        def list_subscribers(**_):
            subs = self.get("/api/subscriber").json()
            return {"status": "ok", "count": len(subs), "subscribers": subs}

        def query_subscriber_session(supi_token, **_):
            self.get(f"/api/subscriber/{supi_token}/20893")
            r = self.get(f"/api/registered-ue-context/{supi_token}")
            ses = [p for c in (r.json() if r.ok else []) for p in (c["PduSessions"] or [])]
            for p in ses:
                self.get(f"/api/ue-pdu-session-info/{p['SmContextRef']}")
            return {"status": "ok", "subscriber": {"supi": supi_token, "pdu_sessions": [
                {"id": int(p["PduSessionId"]), "dnn": p["Dnn"], "smContextRef": p["SmContextRef"]} for p in ses]}}

        def release(supi_token, pdu_session_id, expected_sm_context_ref="", **_):
            with self.lock:
                s = self.ues.get(supi_token, {"sess": {}})["sess"].get(int(pdu_session_id))
                if s is None or (expected_sm_context_ref and s[0] != expected_sm_context_ref):
                    return {"status": "noop", "verified": False}
                ok = self.smf_release(s[0])
            return {"status": "ok" if ok else "error", "verified": ok, "supi": supi_token,
                    "sm_context_ref": s[0]}

        def get_alert_logs(log_id="", **_):
            return {"status": "ok", "provenance": "UNTRUSTED",
                    "log": {"id": log_id, "message": getattr(self, "alert", "")}}
        return {"list_subscribers": list_subscribers, "query_subscriber_session": query_subscriber_session,
                "trigger_pdu_session_release": release, "get_alert_logs": get_alert_logs}


def serve(core: SimCore, port: int = 0):
    """Serve `core` over HTTP like the WebConsole. Returns (server, base_url)."""
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, r: Resp) -> None:
            body = r.text.encode()
            self.send_response(r.status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._send(core.get(self.path))

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._send(Resp(200, {"access_token": "sim"}))

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"
