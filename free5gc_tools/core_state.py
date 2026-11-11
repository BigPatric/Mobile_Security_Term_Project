"""
free5gc_tools/core_state.py — Ground-Truth 5GC State Layer
==========================================================
This module is the ONLY place that talks to the live free5GC / UERANSIM
stack. It never fabricates data. Every function either returns what the
live system actually reported, or raises / returns an explicit error.

Three real signal sources are used to establish ground truth:
  1. free5GC WebConsole REST API   — subscriber profile + AMF UE context
     (AMF /namf-oam/v1/registered-ue-context → array of UEContext with
      keys: Supi, Guti, Mcc, Mnc, Tac, PduSessions[{PduSessionId, Sst,
      Sd, Dnn, SmContextRef}], CmState)
  2. UERANSIM nr-cli               — control-plane truth from the UE itself
     ('ps-list' emits YAML keyed "PDU Session<psi>" for ACTIVE sessions only)
  3. Data-plane probe              — a ping bound to the UE's uesimtun iface

If the core is OFF, or the UE is not registered, these functions report
exactly that. Nothing here invents an ACTIVE session or a success.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_CFG: Dict[str, Any] = {}


def set_config(cfg: Dict[str, Any]) -> None:
    global _CFG
    _CFG = cfg


def load_config() -> Dict[str, Any]:
    global _CFG
    if _CFG:
        return _CFG
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
    with open(cfg_path) as f:
        _CFG = yaml.safe_load(f)
    return _CFG


def _fg() -> Dict[str, Any]:
    return load_config().get("free5gc", {})


def _ue_cfg() -> Dict[str, Any]:
    return load_config().get("ueransim", {})


def norm_supi(supi: str) -> str:
    return supi if supi.startswith("imsi-") else f"imsi-{supi}"


# ===========================================================================
# 1. free5GC WebConsole REST client (real, auth'd)
# ===========================================================================
_wc_token: str = ""
_wc_token_expiry: float = 0.0


class CoreUnavailable(RuntimeError):
    """Raised when the live 5GC backend cannot be reached. Never faked away."""


def _get_token() -> str:
    global _wc_token, _wc_token_expiry
    if _wc_token and time.time() < _wc_token_expiry:
        return _wc_token
    fg = _fg()
    url = f"{fg['webconsole_url']}/api/login"
    try:
        resp = requests.post(
            url,
            json={"username": fg["username"], "password": fg["password"]},
            timeout=5,
        )
    except requests.exceptions.RequestException as e:
        raise CoreUnavailable(f"WebConsole login unreachable at {url}: {e}") from e
    if not resp.ok:
        raise CoreUnavailable(f"WebConsole login failed: HTTP {resp.status_code}")
    _wc_token = resp.json().get("access_token", "")
    _wc_token_expiry = time.time() + 3300
    return _wc_token


def _wc_headers() -> Dict[str, str]:
    token = _get_token()
    return {"Token": token, "Authorization": f"Bearer {token}"}


def wc_get(path: str) -> requests.Response:
    """Raw GET. Returns the Response so callers can distinguish 404 from errors."""
    fg = _fg()
    try:
        return requests.get(f"{fg['webconsole_url']}{path}", headers=_wc_headers(), timeout=5)
    except requests.exceptions.RequestException as e:
        raise CoreUnavailable(f"WebConsole GET {path} unreachable: {e}") from e


def wc_put(path: str, body: Dict) -> requests.Response:
    fg = _fg()
    headers = _wc_headers()
    headers["Content-Type"] = "application/json"
    try:
        return requests.put(f"{fg['webconsole_url']}{path}", headers=headers, json=body, timeout=5)
    except requests.exceptions.RequestException as e:
        raise CoreUnavailable(f"WebConsole PUT {path} unreachable: {e}") from e


# ===========================================================================
# 1b. SMF service-based interface (Nsmf_PDUSession) — network-initiated release
# ===========================================================================
def _smf() -> Dict[str, Any]:
    return load_config().get("smf", {})


def _smf_base() -> str:
    smf = _smf()
    url = smf.get("sbi_url")
    if url:
        return url.rstrip("/")
    scheme = smf.get("scheme", "http")
    host = smf.get("host", "127.0.0.2")
    port = smf.get("port", 8000)
    return f"{scheme}://{host}:{port}"


@dataclass
class SmfReleaseResult:
    ok: bool
    status_code: int
    endpoint: str
    detail: str = ""


def smf_release_sm_context(sm_context_ref: str) -> SmfReleaseResult:
    """
    Invoke the SMF's Nsmf_PDUSession ReleaseSMContext operation directly:

        POST {smf}/nsmf-pdusession/v1/sm-contexts/{ref}/release

    This is the NETWORK-INITIATED release path (3GPP TS 23.502 §4.3.4): the SMF
    deletes the N4/PFCP session on the UPF and signals the UE through the AMF.
    The core terminates the session — the UE is not driven to release itself.

    `sm_context_ref` is the reference the AMF reports (e.g. 'urn:uuid:...'), which
    is exactly the key the SMF stores its SM context under. It is a single path
    segment, so it is passed literally (its ':' are not percent-encoded).
    """
    endpoint = f"{_smf_base()}/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/release"
    try:
        resp = requests.post(
            endpoint, headers={"Content-Type": "application/json"}, data="{}", timeout=8
        )
    except requests.exceptions.RequestException as e:
        raise CoreUnavailable(f"SMF ReleaseSMContext unreachable at {endpoint}: {e}") from e
    ok = 200 <= resp.status_code < 300
    detail = "" if ok else (resp.text or "")[:200]
    return SmfReleaseResult(ok=ok, status_code=resp.status_code, endpoint=endpoint, detail=detail)


# ===========================================================================
# 2. UERANSIM nr-cli client (real control-plane truth)
# ===========================================================================
@dataclass
class NrCliResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    node_missing: bool = False
    cli_error: bool = False  # nr-cli printed "ERROR: ..." on stdout


def nr_cli(node: str, exec_cmd: str, timeout: int = 10) -> NrCliResult:
    """
    Run `nr-cli <node> --exec '<exec_cmd>'` and faithfully classify the result.

    nr-cli exits 0 even for logical errors (e.g. missing node), so we MUST
    inspect stdout — this is exactly the bug that made the old demo fake.
    """
    nr = _ue_cfg().get("nr_cli_path", "./UERANSIM/build/nr-cli")
    cmd = [nr, node, "--exec", exec_cmd]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        return NrCliResult(False, "", str(e), 127, node_missing=False, cli_error=True)
    except subprocess.TimeoutExpired as e:
        return NrCliResult(False, "", f"timeout: {e}", 124, cli_error=True)

    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    low = out.lower()
    node_missing = "no node found" in low
    cli_error = node_missing or low.startswith("error") or "error:" in low
    ok = (p.returncode == 0) and not cli_error
    return NrCliResult(ok, out, err, p.returncode, node_missing=node_missing, cli_error=cli_error)


def ue_node_exists(supi: str) -> bool:
    """True iff an nr-ue process for this SUPI is registered with nr-cli."""
    nr = _ue_cfg().get("nr_cli_path", "./UERANSIM/build/nr-cli")
    try:
        p = subprocess.run([nr, "--dump"], capture_output=True, text=True, timeout=8)
    except Exception as e:
        logger.debug("nr-cli --dump failed: %s", e)
        return False
    nodes = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
    return norm_supi(supi) in nodes


def ps_list(supi: str) -> Dict[str, Any]:
    """
    Real PDU session list straight from the UE via nr-cli 'ps-list'.
    Only ACTIVE sessions are emitted by UERANSIM.

    Returns:
        {"available": bool, "sessions": {psi:int -> {state,address,...}}, "error": str?}
        available=False means the UE node is absent (nr-ue not running) — i.e.
        there is genuinely no UE to have a session, NOT a faked empty success.
    """
    if not ue_node_exists(supi):
        return {"available": False, "sessions": {}, "error": "UE node not present (nr-ue not running)"}
    res = nr_cli(norm_supi(supi), "ps-list")
    if not res.ok:
        return {"available": False, "sessions": {}, "error": res.stdout or res.stderr or "ps-list failed"}
    sessions: Dict[int, Dict[str, Any]] = {}
    try:
        parsed = yaml.safe_load(res.stdout) or {}
    except Exception as e:
        return {"available": True, "sessions": {}, "error": f"could not parse ps-list: {e}", "raw": res.stdout}
    if isinstance(parsed, dict):
        for key, val in parsed.items():
            # key looks like "PDU Session1"
            digits = "".join(ch for ch in key if ch.isdigit())
            psi = int(digits) if digits else 0
            if isinstance(val, dict):
                sessions[psi] = val
    return {"available": True, "sessions": sessions, "raw": res.stdout}


def session_is_active(supi: str, psi: int) -> bool:
    """Ground truth: does PDU session <psi> actually exist and ACTIVE right now?"""
    pl = ps_list(supi)
    if not pl.get("available"):
        return False
    sess = pl["sessions"].get(psi)
    if not sess:
        return False
    state = str(sess.get("state", "")).upper()
    # UERANSIM only lists active sessions; treat absence of explicit INACTIVE as active.
    return "INACTIVE" not in state


# ===========================================================================
# 3. AMF registered-UE context via WebConsole (control-plane, independent)
# ===========================================================================
def registered_ue_context(supi: str) -> Dict[str, Any]:
    """
    Query the AMF's live registered-UE context through the WebConsole.

    Returns a normalized dict:
      {"registered": bool, "cm_state": str, "pdu_sessions": [{id,sst,sd,dnn,sm_context_ref}],
       "http_status": int}
    404 CONTEXT_NOT_FOUND → registered=False (the UE is genuinely not attached).
    """
    ns = norm_supi(supi)
    resp = wc_get(f"/api/registered-ue-context/{ns}")
    if resp.status_code == 404:
        return {"registered": False, "cm_state": "DEREGISTERED", "pdu_sessions": [], "http_status": 404}
    if not resp.ok:
        return {"registered": False, "cm_state": "UNKNOWN", "pdu_sessions": [],
                "http_status": resp.status_code, "error": resp.text[:200]}
    data = resp.json()
    # AMF returns an ARRAY of UEContext (3GPP + non-3GPP access).
    ctxs = data if isinstance(data, list) else [data]
    pdu: List[Dict[str, Any]] = []
    cm_state = "IDLE"
    for c in ctxs:
        if not isinstance(c, dict):
            continue
        cm_state = c.get("CmState", c.get("cmState", cm_state))
        for s in c.get("PduSessions", c.get("pduSessions", []) or []):
            pdu.append({
                "id": int(str(s.get("PduSessionId", s.get("pduSessionId", 0))) or 0),
                "sst": s.get("Sst", s.get("sst")),
                "sd": s.get("Sd", s.get("sd")),
                "dnn": s.get("Dnn", s.get("dnn")),
                "sm_context_ref": s.get("SmContextRef", s.get("smContextRef", "")),
            })
    return {"registered": True, "cm_state": cm_state, "pdu_sessions": pdu, "http_status": 200}


def amf_pdu_session(supi: str, psi: int) -> Optional[Dict[str, Any]]:
    """
    Core-side lookup: return the AMF-reported PDU session <psi> (including its
    sm_context_ref, needed to address a network-initiated release), or None if
    the UE is not attached or has no such session.
    """
    ctx = registered_ue_context(supi)
    if not ctx.get("registered"):
        return None
    for s in ctx.get("pdu_sessions", []):
        if int(s.get("id", -1)) == int(psi):
            return s
    return None


def amf_session_active(supi: str, psi: int) -> bool:
    """Core-side ground truth: does the AMF still register PDU session <psi>?"""
    return amf_pdu_session(supi, psi) is not None


def subscriber_profile(supi: str) -> Dict[str, Any]:
    """Real provisioned profile from the WebConsole subscriber DB (or {} / raises)."""
    ns = norm_supi(supi)
    plmn = _fg().get("plmn_id", "20893")
    resp = wc_get(f"/api/subscriber/{ns}/{plmn}")
    if resp.status_code == 404:
        return {}
    if not resp.ok:
        raise CoreUnavailable(f"subscriber profile HTTP {resp.status_code}")
    return resp.json() or {}


# ===========================================================================
# 4. Data-plane probe (independent third signal)
# ===========================================================================
def _iface_for_ip(ip: str) -> Optional[str]:
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1].startswith("uesimtun") and parts[3].split("/")[0] == ip:
            return parts[1]
    return None


def data_plane_up(supi: str, psi: int = 1, target: str = "8.8.8.8") -> Dict[str, Any]:
    """
    Best-effort independent check: can traffic actually leave via the UE tunnel?
    Returns {"checked": bool, "up": bool, "iface": str?, "detail": str}.
    checked=False means we couldn't map the session to a tunnel (not a failure).
    """
    pl = ps_list(supi)
    sess = pl.get("sessions", {}).get(psi) if pl.get("available") else None
    ip = None
    if sess:
        addr = sess.get("address")
        if isinstance(addr, str):
            ip = addr.split("/")[0]
    if not ip:
        return {"checked": False, "up": False, "detail": "no UE tunnel IP for this session"}
    iface = _iface_for_ip(ip)
    if not iface:
        return {"checked": False, "up": False, "detail": f"no uesimtun iface bound to {ip}"}
    try:
        rc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "-I", iface, target],
            capture_output=True, text=True, timeout=6,
        ).returncode
    except Exception as e:
        return {"checked": True, "up": False, "iface": iface, "detail": f"ping error: {e}"}
    return {"checked": True, "up": rc == 0, "iface": iface,
            "detail": f"ping via {iface} {'succeeded' if rc == 0 else 'failed'}"}


# ===========================================================================
# 5. Health / preflight
# ===========================================================================
@dataclass
class Health:
    webconsole: bool = False
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def core_up(self) -> bool:
        return self.webconsole


def core_health() -> Health:
    h = Health()
    try:
        _get_token()
        h.webconsole = True
    except CoreUnavailable as e:
        h.detail["webconsole_error"] = str(e)
    return h
