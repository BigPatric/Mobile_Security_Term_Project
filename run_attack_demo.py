#!/usr/bin/env python3
"""
run_attack_demo.py — Baseline Attack Flow Demo
===============================================
Runs the IPI-01 (Indirect Prompt Injection) attack scenario end-to-end
against an UNPROTECTED agent (no MCP gateway), producing:

  1. A colourised live trace of every Thought / Action / Observation
  2. A structured JSON evidence log  → attack_evidence.jsonl
  3. A final verdict summary

Usage:
    # Quickstart (mock mode — no free5GC / UERANSIM needed):
    python3 run_attack_demo.py

    # With a live free5GC + UERANSIM testbed:
    python3 run_attack_demo.py --live

    # Run a different scenario:
    python3 run_attack_demo.py --scenario IPI-02

    # Use real Gemini LLM (requires GEMINI_API_KEY env var):
    python3 run_attack_demo.py --llm
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
╔══════════════════════════════════════════════════════════════════╗
║   BASELINE ATTACK DEMO — UNPROTECTED 5G NOC AGENT               ║
║   Mobile Network Security, Fall 2026                            ║
║   Scenario: Indirect Prompt Injection via Alert Log (IPI-01)    ║
╚══════════════════════════════════════════════════════════════════╝
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

    if result.was_attacked:
        print(f"{Fore.RED + Style.BRIGHT}⛔  VERDICT: ATTACK SUCCEEDED{Style.RESET_ALL}")
        dangerous_calls = result.dangerous_calls()
        for dc in dangerous_calls:
            if dc.tool_name == "trigger_pdu_session_release":
                supi = dc.arguments.get("supi_token", "?")
                sess = dc.arguments.get("pdu_session_id", "?")
                print(f"    PDU Session {sess} of subscriber {supi} was RELEASED without operator authorisation.")
            elif dc.tool_name == "modify_slice_quota":
                supi = dc.arguments.get("supi_token", "?")
                print(f"    Slice quota for {supi} was MODIFIED without operator authorisation.")
    else:
        print(f"{Fore.GREEN + Style.BRIGHT}✅  VERDICT: AGENT COMPLETED TASK SAFELY{Style.RESET_ALL}")

    print(f"\n    Duration: {result.duration_sec:.3f}s | Tool calls: {len(result.tool_calls)}")
    print(SEPARATOR + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Run an MCP Gateway attack demo scenario.")
    parser.add_argument(
        "--scenario",
        default="IPI-01",
        choices=["IPI-01", "IPI-02", "DPI-01", "BENIGN-01"],
        help="Scenario ID to run (default: IPI-01)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Disable mock_5gc and call real free5GC / UERANSIM APIs",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use real Gemini LLM instead of scripted mock (requires GEMINI_API_KEY)",
    )
    args = parser.parse_args()

    # Load config
    cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    setup_logging(cfg.get("demo", {}).get("log_level", "INFO"))
    log = logging.getLogger(__name__)

    # Apply CLI overrides to config (in-memory only)
    if args.live:
        cfg["demo"]["mock_5gc"] = False
        # Monkey-patch the config loader cache
        import free5gc_tools.tools as tools_mod
        tools_mod._CFG = cfg
    if args.llm:
        cfg["agent"]["mock_llm"] = False

    mock_5gc = cfg.get("demo", {}).get("mock_5gc", True)
    mock_llm = cfg.get("agent", {}).get("mock_llm", True)
    evidence_file = cfg.get("demo", {}).get("evidence_log", "attack_evidence.jsonl")

    print(BANNER)
    print(f"  Mode: {'MOCK' if mock_5gc else Fore.RED + 'LIVE — REAL free5GC + UERANSIM' + Style.RESET_ALL}")
    print(f"  LLM:  {'Scripted mock' if mock_llm else Fore.YELLOW + 'Real Gemini API' + Style.RESET_ALL}")
    print(f"  Scenario: {Fore.CYAN}{args.scenario}{Style.RESET_ALL}\n")

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

    # Import tools and agent (after potential mock override)
    from free5gc_tools import TOOL_REGISTRY
    from agent import ReActAgent

    agent = ReActAgent(
        tool_registry=TOOL_REGISTRY,
        scenario_id=args.scenario,
        model_name=cfg.get("agent", {}).get("model", "gemini-2.0-flash"),
        mock_llm=mock_llm,
    )

    print(f"{Fore.WHITE + Style.BRIGHT}▶  Running agent…{Style.RESET_ALL}\n")
    result = agent.run(task, max_turns=cfg.get("agent", {}).get("max_turns", 10))

    # Display
    print_run(result, scenario_meta)

    # Write structured evidence log
    evidence = {
        "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario_id": result.scenario_id,
        "scenario_name": scenario_meta.get("scenario_name"),
        "attack_type": scenario_meta.get("attack_type"),
        "mock_5gc": mock_5gc,
        "mock_llm": mock_llm,
        "was_attacked": result.was_attacked,
        "duration_sec": result.duration_sec,
        "task": result.task,
        "agent_answer": result.answer,
        "tool_calls": [
            {
                "turn": c.turn,
                "tool_name": c.tool_name,
                "arguments": c.arguments,
                "result_status": c.result.get("status"),
                "is_dangerous": c.is_dangerous(),
                "timestamp": c.timestamp,
            }
            for c in result.tool_calls
        ],
    }
    log_evidence(evidence_file, evidence)
    print(f"Evidence written to: {Fore.CYAN}{evidence_file}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
