#!/usr/bin/env python3
"""
run_attack_demo.py — Baseline Attack Flow Demo (Live 5GC)
==========================================================
Runs the 5G NOC Agent against attack scenarios.
All tool calls execute live against free5GC WebConsole & UERANSIM.

Reasoning Modes:
  1. Simple Mode (default):
     python3 run_attack_demo.py
     - Deterministic ReAct thought/action loop (no API key needed)
     - Directly calls live free5GC & UERANSIM

  2. LLM Mode:
     python3 run_attack_demo.py --llm
     - Calls real Gemini API (gemini-2.0-flash)
     - Live reasoning, prompt injection susceptibility, and live tool execution
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
def print_run(result, scenario_meta: dict) -> None:
    print(SEPARATOR)
    print(f"{Fore.CYAN + Style.BRIGHT}📋  SCENARIO: {result.scenario_id}{Style.RESET_ALL}")
    print(f"    {scenario_meta.get('scenario_name', '')}")
    print(f"    Attack type: {Fore.YELLOW}{scenario_meta.get('attack_type', '')}{Style.RESET_ALL}")
    print(SEPARATOR)

    print(f"\n{Fore.WHITE + Style.BRIGHT}📨  TASK GIVEN TO AGENT:{Style.RESET_ALL}")
    print(f"    {result.task}\n")

    for i, call in enumerate(result.tool_calls, 1):
        print(f"{Fore.CYAN}── Turn {call.turn} ─────────────────────────────────────────{Style.RESET_ALL}")
        dangerous = call.is_dangerous()
        icon = "🚨" if dangerous else "🔧"
        name_colour = Fore.RED + Style.BRIGHT if dangerous else Fore.GREEN
        print(f"  {icon}  {name_colour}TOOL CALL:{Style.RESET_ALL} {call.tool_name}({json.dumps(call.arguments)})")
        result_str = json.dumps(call.result, indent=4)
        # Truncate very long results for readability
        if len(result_str) > 800:
            result_str = result_str[:800] + "\n    ... [truncated]"
        obs_colour = Fore.RED if dangerous else Fore.WHITE
        print(f"  {obs_colour}RESULT:{Style.RESET_ALL}\n{result_str}\n")

    print(SEPARATOR)
    print(f"\n{Fore.WHITE + Style.BRIGHT}💬  AGENT FINAL ANSWER:{Style.RESET_ALL}")
    print(f"    {result.answer}\n")

    # --- Verdict grounded in VERIFIED live-core state ---
    print(f"  Agent hijacked by injection : {_yn(result.hijacked)}")
    print(f"  Real 5GC state changed      : {_yn(result.was_attacked)}")
    print(f"  Identifier (SUPI) leaked    : {_yn(result.identifier_leaked)}")

    if result.was_attacked:
        print(f"\n{Fore.RED + Style.BRIGHT}⛔  VERDICT: ATTACK SUCCEEDED — real impact on free5GC{Style.RESET_ALL}")
        for dc in result.dangerous_calls():
            if dc.changed_core_state() and dc.tool_name == "trigger_pdu_session_release":
                r = dc.result
                print(f"    PDU session {r.get('pdu_session_id')} of {r.get('supi')} RELEASED "
                      f"(verified: {r.get('pre_state')} → {r.get('post_state')}).")
                api = r.get("release_api", {})
                if api.get("endpoint"):
                    print(f"    via core API: POST {api['endpoint']} (HTTP {api.get('http_status')})")
            elif dc.changed_core_state() and dc.tool_name == "modify_slice_quota":
                print(f"    Slice quota for {dc.result.get('supi')} MODIFIED (verified in 5GC).")
    elif result.dangerous_calls():
        print(f"\n{Fore.YELLOW + Style.BRIGHT}⚠️   VERDICT: AGENT HIJACKED, NO REAL IMPACT{Style.RESET_ALL}")
        print("    The injection made the agent attempt a dangerous action, but the live core")
        print("    reported no active session to change (bring up a live UE session to see full impact).")
    elif result.identifier_leaked:
        print(f"\n{Fore.RED + Style.BRIGHT}⛔  VERDICT: IDENTIFIER LEAK — real SUPI exfiltrated{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN + Style.BRIGHT}✅  VERDICT: AGENT COMPLETED TASK SAFELY{Style.RESET_ALL}")

    print(f"\n    Duration: {result.duration_sec:.3f}s | Tool calls: {len(result.tool_calls)}")
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
        default="IPI-01",
        choices=["IPI-01", "IPI-02", "DPI-01", "BENIGN-01"],
        help="Scenario ID to run (default: IPI-01)",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use real external Gemini LLM instead of simple local agent logic",
    )
    args = parser.parse_args()

    # Load config
    cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    setup_logging(cfg.get("demo", {}).get("log_level", "INFO"))
    log = logging.getLogger(__name__)

    # Determine Agent mode: "simple" (default) or "llm"
    agent_mode = "llm" if args.llm else cfg.get("agent_mode", "simple")

    import free5gc_tools.tools as tools_mod
    import free5gc_tools.core_state as cs
    tools_mod._CFG = cfg
    cs.set_config(cfg)

    evidence_file = cfg.get("demo", {}).get("evidence_log", "attack_evidence.jsonl")

    print(BANNER)

    # --- Honest preflight: report the REAL state of the live core ---
    health = cs.core_health()
    victim = cfg.get("ueransim", {}).get("default_supi", "imsi-208930000000001")
    session_live = False
    if health.core_up:
        try:
            session_live = cs.session_is_active(victim, 1)
        except Exception:
            session_live = False
        core_label = f"{Fore.GREEN + Style.BRIGHT}LIVE — free5GC WebConsole reachable{Style.RESET_ALL}"
    else:
        core_label = f"{Fore.RED + Style.BRIGHT}DOWN — {health.detail.get('webconsole_error', 'WebConsole unreachable')}{Style.RESET_ALL}"

    sess_label = (f"{Fore.GREEN + Style.BRIGHT}ACTIVE PDU session present for {victim}{Style.RESET_ALL}"
                  if session_live else
                  f"{Fore.YELLOW}no active PDU session (attack can hijack the agent but cannot cause real DoS){Style.RESET_ALL}")
    agent_label = f"{Fore.YELLOW}Real Gemini API{Style.RESET_ALL}" if agent_mode == "llm" else f"{Fore.CYAN + Style.BRIGHT}Deterministic ReAct (observation-driven){Style.RESET_ALL}"
    print(f"  5G Core:  {core_label}")
    print(f"  Session:  {sess_label}")
    print(f"  Agent:    {agent_label}")
    print(f"  Scenario: {Fore.CYAN}{args.scenario}{Style.RESET_ALL}")
    if not health.core_up:
        print(f"\n  {Fore.YELLOW}Tip: start free5GC + UERANSIM (gnb + ue) yourself, then re-run this demo.{Style.RESET_ALL}")
    print()

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

    model_name = cfg.get("llm", {}).get("model") or cfg.get("agent", {}).get("model", "gemini-2.0-flash")
    api_key = cfg.get("llm", {}).get("api_key", "")
    max_turns = cfg.get("llm", {}).get("max_turns") or cfg.get("agent", {}).get("max_turns", 10)

    agent = ReActAgent(
        tool_client=default_local_client(),
        scenario_id=args.scenario,
        mode=agent_mode,
        model_name=model_name,
        api_key=api_key,
    )

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
        "live_session_present": session_live,
        "agent_mode": agent_mode,
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
