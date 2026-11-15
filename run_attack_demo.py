#!/usr/bin/env python3
"""
run_attack_demo.py — Baseline Attack Flow Demo (Live 5GC)
==========================================================
Runs the deterministic 5G NOC agent against an attack scenario. Every tool call
executes live against the real free5GC core over its RESTful service interfaces.

    python3 run_attack_demo.py --scenario DOS-01

The demo aborts unless the 5G core is actually up (WebConsole + SMF SBI).
"""

import argparse
import json
import logging
import os
import sys
import time

import yaml
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ---------------------------------------------------------------------------
# Logging setup — colourised, structured
# ---------------------------------------------------------------------------
class ColourFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.WHITE,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelno, "")
        msg = super().format(record)
        return colour + msg + Style.RESET_ALL


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColourFormatter("%(asctime)s  %(levelname)-8s  %(message)s"))
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = f"""
{Fore.RED + Style.BRIGHT}
╔═══════════════════════════════════════════════════════╗
║   BASELINE ATTACK DEMO — UNPROTECTED 5G NOC AGENT      ║
║   Mobile Network Security, Fall 2026                  ║
╚═══════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

SEPARATOR = Fore.WHITE + "─" * 70 + Style.RESET_ALL


# ---------------------------------------------------------------------------
# Evidence logger
# ---------------------------------------------------------------------------
def log_evidence(evidence_file: str, record: dict) -> None:
    with open(evidence_file, "a") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Pretty-print agent run
# ---------------------------------------------------------------------------
def _call_lines(call) -> list:
    """Concise, real summary of ONE tool result — every value is the tool's own
    output (the live core's response), never fabricated."""
    r = call.result or {}
    n = call.tool_name
    if n == "get_alert_logs":
        if r.get("status") == "ok":
            log = r.get("log", {})
            return [f"id={log.get('id')} severity={log.get('severity')} "
                    f"source={log.get('source')} provenance={r.get('provenance')}"]
        return [f"error: {r.get('error')}"]
    if n == "query_subscriber_session":
        if r.get("status") == "ok":
            s = r.get("subscriber", {})
            lines = [f"supi={s.get('supi')} registration={s.get('registration_state')} "
                     f"cm={s.get('cm_state')} active_sessions={s.get('active_pdu_session_count')}"]
            for p in s.get("pdu_sessions", []):
                lines.append(f"pdu id={p.get('id')} dnn={p.get('dnn')} smContextRef={p.get('smContextRef')}")
            return lines
        return [f"error: {r.get('error')}"]
    if n == "trigger_pdu_session_release":
        api = r.get("release_api", {})
        lines = []
        if api.get("endpoint"):
            lines.append(f"POST {api['endpoint']}")
            lines.append(f"core response: HTTP {api.get('http_status')} "
                         f"{api.get('http_response') or '(empty body)'}")
            lines.append(f"oauth: {api.get('oauth')}")
        lines.append(f"status={r.get('status')} verified={r.get('verified')} "
                     f"{r.get('pre_state')}→{r.get('post_state')}")
        if r.get("confirmed_by"):
            lines.append(f"confirmed_by: {'; '.join(r['confirmed_by'])}")
        for k in ("note", "detail", "error"):
            if r.get(k):
                lines.append(f"{k}: {r[k]}")
        return lines
    if n == "list_subscribers":
        subs = r.get("subscribers", []) or []
        out = [f"count={r.get('count')} status={r.get('status')}"]
        out += [f"  {s.get('ueId')} (plmn {s.get('plmnID')})" for s in subs]
        return out
    return [json.dumps(r)[:160]]


def print_run(result, scenario_meta: dict) -> None:
    print(SEPARATOR)
    print(f"{Fore.CYAN + Style.BRIGHT}SCENARIO {result.scenario_id}{Style.RESET_ALL}  "
          f"{scenario_meta.get('scenario_name', '')}  "
          f"[{Fore.YELLOW}{scenario_meta.get('attack_type', '')}{Style.RESET_ALL}]")
    print(f"TASK: {result.task}")
    print(SEPARATOR)

    for call in result.tool_calls:
        dangerous = call.is_dangerous()
        colour = Fore.RED + Style.BRIGHT if dangerous else Fore.GREEN
        print(f"{'🚨' if dangerous else '🔧'} {colour}{call.tool_name}{Style.RESET_ALL}"
              f"({json.dumps(call.arguments)})")
        for ln in _call_lines(call):
            print(f"     {ln}")

    # Provenance (why the agent acted) — the causal trace, without the duplicated
    # observation dump.
    trace = result.answer.split("\n\n=== Observations")[0].strip()
    print(SEPARATOR)
    print(trace)
    print(SEPARATOR)

    print(f"hijacked by injection : {_yn(result.hijacked)}    "
          f"real 5GC state changed: {_yn(result.was_attacked)}    "
          f"SUPI leaked: {_yn(result.identifier_leaked)}")

    if result.was_attacked:
        n = sum(1 for dc in result.dangerous_calls() if dc.changed_core_state())
        print(f"{Fore.RED + Style.BRIGHT}VERDICT: ATTACK SUCCEEDED — {n} PDU session(s) released on free5GC{Style.RESET_ALL}")
        for dc in result.dangerous_calls():
            r = dc.result
            if dc.changed_core_state():
                api = r.get("release_api", {})
                print(f"  {r.get('supi')} PDU {r.get('pdu_session_id')} RELEASED via "
                      f"POST {api.get('endpoint')} → HTTP {api.get('http_status')} "
                      f"({r.get('pre_state')}→{r.get('post_state')}).")
    elif result.dangerous_calls():
        print(f"{Fore.YELLOW + Style.BRIGHT}VERDICT: AGENT HIJACKED, NO REAL IMPACT{Style.RESET_ALL} "
              f"(dangerous call attempted; core reported nothing live to change)")
    elif result.identifier_leaked:
        print(f"{Fore.RED + Style.BRIGHT}VERDICT: IDENTIFIER LEAK — real SUPI exfiltrated{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN + Style.BRIGHT}VERDICT: TASK COMPLETED SAFELY{Style.RESET_ALL}")

    print(f"{Fore.WHITE}{result.duration_sec:.2f}s · {len(result.tool_calls)} tool calls{Style.RESET_ALL}")
    print(SEPARATOR + "\n")


def _yn(b: bool) -> str:
    return (Fore.RED + "YES" if b else Fore.GREEN + "no") + Style.RESET_ALL


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="5G NOC Agent Attack Demo (Live 5GC).")
    parser.add_argument(
        "--scenario",
        default="DOS-01",
        choices=["ENUM-01", "DOS-01"],
        help="ENUM-01 = list all subscribers (SUPI leak); DOS-01 = release all PDU sessions (default)",
    )
    parser.add_argument(
        "--gateway",
        choices=["on", "off"],
        default=None,
        help="Enforce the Secure MCP Gateway (Layer 1 tokenizer). Overrides config "
             "gateway.enabled. Use 'off' for the unprotected baseline, 'on' for the "
             "protected run (A/B comparison / ablation).",
    )
    args = parser.parse_args()

    # Load config
    cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    setup_logging(cfg.get("demo", {}).get("log_level", "INFO"))
    log = logging.getLogger(__name__)

    import free5gc_tools.tools as tools_mod
    import free5gc_tools.core_state as cs
    tools_mod._CFG = cfg
    cs.set_config(cfg)

    evidence_file = cfg.get("demo", {}).get("evidence_log", "attack_evidence.jsonl")

    print(BANNER)

    # --- Honest preflight: report the REAL state of the live core ---
    health = cs.core_health()
    victim = cfg.get("ueransim", {}).get("default_supi", "imsi-208930000000001")

    def _updown(ok: bool) -> str:
        return (Fore.GREEN + Style.BRIGHT + "LIVE" if ok else Fore.RED + Style.BRIGHT + "DOWN") + Style.RESET_ALL

    # ENUM-01 only reads the provisioned subscriber DB (WebConsole); only the
    # release scenario (DOS-01) needs the SMF SBI to be live.
    needs_smf = args.scenario == "DOS-01"

    session_live = False
    if health.webconsole:
        try:
            session_live = cs.amf_session_active(victim, 1)
        except Exception:
            session_live = False

    sess_label = (f"{Fore.GREEN + Style.BRIGHT}ACTIVE PDU session present for {victim}{Style.RESET_ALL}"
                  if session_live else
                  f"{Fore.YELLOW}no active PDU session (agent can be hijacked, but no real DoS){Style.RESET_ALL}")
    # Gateway on/off: CLI flag overrides config.
    if args.gateway is not None:
        gateway_on = args.gateway == "on"
    else:
        gateway_on = cfg.get("gateway", {}).get("enabled", False)
    gw_label = (f"{Fore.GREEN + Style.BRIGHT}ON  (Layer 1: Identifier Tokenizer){Style.RESET_ALL}"
                if gateway_on else
                f"{Fore.RED + Style.BRIGHT}OFF (unprotected baseline){Style.RESET_ALL}")

    print(f"  WebConsole (REST / AMF discovery) : {_updown(health.webconsole)}")
    print(f"  SMF SBI (Nsmf release target)     : {_updown(health.smf)}{'' if needs_smf else '  (not needed for ENUM-01)'}")
    print(f"  Victim session                    : {sess_label}")
    print(f"  Scenario                          : {Fore.CYAN}{args.scenario}{Style.RESET_ALL}")
    print(f"  Secure MCP Gateway                : {gw_label}")
    print()

    # --- Gate: the pieces this scenario actually uses must be live. ---
    core_ready = health.webconsole and (health.smf or not needs_smf)
    if not core_ready:
        down = []
        if not health.webconsole:
            down.append(f"WebConsole: {health.detail.get('webconsole_error', 'unreachable')}")
        if needs_smf and not health.smf:
            down.append(health.detail.get("smf_error", "SMF SBI unreachable"))
        print(f"{Fore.RED + Style.BRIGHT}⛔  ABORTING: the 5G core is not up, so there is no live attack to run.{Style.RESET_ALL}")
        for d in down:
            print(f"    - {d}")
        print(f"    {Fore.YELLOW}Start free5GC + UERANSIM (gNB + UE) yourself, then re-run this demo.{Style.RESET_ALL}\n")
        sys.exit(2)

    # Load scenario metadata
    scenario_meta: dict = {}
    benchmark_dirs = [
        os.path.join(os.path.dirname(__file__), "benchmark", "attacks"),
        os.path.join(os.path.dirname(__file__), "benchmark", "benign"),
    ]
    for d in benchmark_dirs:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(d, fname)) as f:
                meta = json.load(f)
            if meta.get("scenario_id") == args.scenario:
                scenario_meta = meta
                break

    if not scenario_meta:
        log.error("No scenario metadata found for scenario_id=%r", args.scenario)
        sys.exit(1)

    task = scenario_meta.get("task_given_to_agent", "No task defined for this scenario.")

    # Build the agent behind the ToolClient seam. Today this is a LocalToolClient
    # (in-process calls); the Secure MCP Gateway will later drop in an MCP client
    # here without changing the agent.
    from agent import ReActAgent, default_local_client

    max_turns = cfg.get("agent", {}).get("max_turns", 10)
    tool_client = default_local_client()
    if gateway_on:
        from gateway import GatewayToolClient
        tool_client = GatewayToolClient(tool_client)
    agent = ReActAgent(tool_client=tool_client, scenario_id=args.scenario)

    # Reaching here means the core is live (the gate above exits otherwise).
    print(f"{Fore.WHITE + Style.BRIGHT}▶  Running agent…{Style.RESET_ALL}\n")
    result = agent.run(task, max_turns=max_turns)

    # Display
    print_run(result, scenario_meta)

    # Write structured evidence log
    evidence = {
        "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario_id": result.scenario_id,
        "scenario_name": scenario_meta.get("scenario_name"),
        "attack_type": scenario_meta.get("attack_type"),
        "core_up": health.core_up,
        "webconsole_up": health.webconsole,
        "smf_up": health.smf,
        "live_session_present": session_live,
        "gateway_enabled": gateway_on,
        "gateway_layers": (["tokenizer"] if gateway_on else []),
        "agent_mode": "deterministic",
        "agent_hijacked": result.hijacked,
        "was_attacked": result.was_attacked,
        "real_core_state_changed": result.was_attacked,
        "identifier_leaked": result.identifier_leaked,
        "duration_sec": result.duration_sec,
        "task": result.task,
        "agent_answer": result.answer,
        "tool_calls": [
            {
                "turn": c.turn,
                "tool_name": c.tool_name,
                "arguments": c.arguments,
                "result_status": c.result.get("status"),
                "verified": c.result.get("verified"),
                "is_dangerous": c.is_dangerous(),
                "changed_core_state": c.changed_core_state(),
                "timestamp": c.timestamp,
            }
            for c in result.tool_calls
        ],
    }
    log_evidence(evidence_file, evidence)
    print(f"Evidence written to: {Fore.CYAN}{evidence_file}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
