#!/usr/bin/env python3
"""
demo_layer2.py — Layer 2 (Taint Tracking) live gateway demo
===========================================================
Shows, against the LIVE free5GC WebConsole, that the Secure MCP Gateway blocks a
DoS (PDU-session release) that was triggered by an injected alert log — WITHOUT
needing an active PDU session, because Layer 2 rejects the call at the gateway
BEFORE it ever reaches the core.

It runs the same three gateway calls twice:
    1. list_subscribers            -> mint a valid token for a real SUPI
    2. get_alert_logs(alert-dos-001) -> read the malicious log (taints the session)
    3. trigger_pdu_session_release -> the injected high-risk action

  * Layer 2 OFF (ablation): the release passes the gateway and hits the core.
  * Layer 2 ON            : the release is BLOCKED at the gateway (L2).

    python3 demo_layer2.py

Only the WebConsole needs to be up (step 1). The SMF / an active UE session are
NOT required, because with L2 on the dangerous call is intercepted first.
"""

import os
import sys

import yaml
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

from agent import default_local_client
from gateway import GatewayToolClient

DOS_LOG = "alert-dos-001"
SEP = Fore.WHITE + "─" * 68 + Style.RESET_ALL


def _load_cfg():
    cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    import free5gc_tools.tools as tools_mod
    import free5gc_tools.core_state as cs
    tools_mod._CFG = cfg
    cs.set_config(cfg)
    return cfg


def _run(enable_taint: bool):
    title = ("LAYER 2 ON  (tokenizer + taint)" if enable_taint
             else "LAYER 2 OFF (ablation: tokenizer only)")
    colour = Fore.GREEN if enable_taint else Fore.RED
    print(SEP)
    print(f"{colour + Style.BRIGHT}{title}{Style.RESET_ALL}")
    print(SEP)

    gw = GatewayToolClient(default_local_client(), enable_taint=enable_taint)

    subs = gw.invoke("list_subscribers", {})
    if subs.get("status") != "ok" or not subs.get("subscribers"):
        print(f"{Fore.RED}Cannot reach free5GC WebConsole (need it up for step 1). "
              f"Got: {subs}{Style.RESET_ALL}")
        sys.exit(2)
    token = subs["subscribers"][0]["ueId"]
    print(f"  1. list_subscribers      -> agent sees token {Fore.CYAN}{token}{Style.RESET_ALL} "
          f"(real SUPI hidden by L1)")

    alert = gw.invoke("get_alert_logs", {"log_id": DOS_LOG})
    prov = alert.get("provenance")
    msg = alert.get("log", {}).get("message", "")
    print(f"  2. get_alert_logs({DOS_LOG}) -> provenance={Fore.YELLOW}{prov}{Style.RESET_ALL}")
    print(f"       injected: {msg}")
    # Surface the TAINT STATE the gateway now holds (not just the eventual block).
    if gw.taint is not None:
        print(f"     {Fore.MAGENTA}↳ gateway taint state:{Style.RESET_ALL}")
        for line in gw.taint.explain().splitlines():
            print(f"        {Fore.MAGENTA}{line}{Style.RESET_ALL}")

    rel = gw.invoke("trigger_pdu_session_release", {"supi_token": token, "pdu_session_id": 1})
    print(f"  3. trigger_pdu_session_release({token}, 1)")
    if rel.get("status") == "blocked":
        print(f"     {Fore.GREEN + Style.BRIGHT}BLOCKED by gateway {rel.get('layer')}{Style.RESET_ALL} "
              f"— core never reached.")
        print(f"       taint kind : {rel.get('taint_kind')}")
        print(f"       tainted by : {rel.get('tainted_by')}")
        print(f"       reason     : {rel.get('reason')}")
    else:
        print(f"     {Fore.RED + Style.BRIGHT}NOT blocked by gateway{Style.RESET_ALL} "
              f"-> call passed to the core (status={rel.get('status')}).")
    print()
    return rel


def main():
    _load_cfg()
    print(f"\n{Fore.CYAN + Style.BRIGHT}Secure MCP Gateway — Layer 2 (Taint) demo{Style.RESET_ALL}")
    print("Same injected-DoS sequence, run with Layer 2 off then on.\n")

    off = _run(enable_taint=False)
    on = _run(enable_taint=True)

    print(SEP)
    off_blocked = off.get("status") == "blocked"
    on_blocked = on.get("status") == "blocked"
    verdict = (f"{Fore.GREEN + Style.BRIGHT}Layer 2 works: the injected release is let through WITHOUT it "
               f"and BLOCKED WITH it.{Style.RESET_ALL}"
               if (not off_blocked and on_blocked) else
               f"{Fore.YELLOW}Unexpected: off_blocked={off_blocked}, on_blocked={on_blocked}{Style.RESET_ALL}")
    print(verdict)
    print(SEP)


if __name__ == "__main__":
    main()
