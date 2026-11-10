#!/usr/bin/env python3
"""
simple_agent.py — 互動式 5G NOC Agent (Live free5GC)
=====================================================
直接透過 free5GC WebConsole REST API 操作真實 5GC 核心網。
不需要外部 LLM API Key — 純 Python CLI 直連 free5GC。

使用方式:
    python3 simple_agent.py

WebConsole API endpoints used:
    POST /api/login
    GET  /api/subscriber
    GET  /api/subscriber/:ueId/:servingPlmnId
    GET  /api/registered-ue-context
    GET  /api/registered-ue-context/:supi
    GET  /api/ue-pdu-session-info/:smContextRef
"""

import json
import subprocess
import sys

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ─────────────────────────────────────────────
# Config (matches config.yaml defaults)
# ─────────────────────────────────────────────
BASE_URL = "http://localhost:5000"
PLMN_ID  = "20893"
USERNAME = "admin"
PASSWORD = "free5gc"


# ─────────────────────────────────────────────
# WebConsole Client
# ─────────────────────────────────────────────
class WebConsoleClient:
    def __init__(self):
        self._token = ""

    def login(self) -> bool:
        try:
            r = requests.post(
                f"{BASE_URL}/api/login",
                json={"username": USERNAME, "password": PASSWORD},
                timeout=5,
            )
            r.raise_for_status()
            self._token = r.json().get("access_token", "")
            print(f"{Fore.GREEN}✓ Logged in to free5GC WebConsole ({BASE_URL}){Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}✗ Login failed: {e}{Style.RESET_ALL}")
            print(f"  → 請先確認 free5GC WebConsole 運行於 {BASE_URL}")
            return False

    def _get(self, path: str):
        headers = {"Authorization": f"Bearer {self._token}"}
        r = requests.get(f"{BASE_URL}/api{path}", headers=headers, timeout=5)
        r.raise_for_status()
        return r.json()

    # ── Tool: list subscribers ──────────────────
    def list_subscribers(self):
        return self._get("/subscriber") or []

    # ── Tool: get subscriber detail ─────────────
    def get_subscriber(self, supi: str):
        bare = supi.replace("imsi-", "")
        return self._get(f"/subscriber/imsi-{bare}/{PLMN_ID}")

    # ── Tool: get registered UE context ─────────
    def get_registered_ue(self, supi: str = ""):
        path = f"/registered-ue-context/{supi}" if supi else "/registered-ue-context"
        return self._get(path) or []

    # ── Tool: get PDU session info ───────────────
    def get_pdu_session(self, sm_context_ref: str):
        return self._get(f"/ue-pdu-session-info/{sm_context_ref}")


# ─────────────────────────────────────────────
# Pretty Printers
# ─────────────────────────────────────────────
def pp(label: str, data):
    print(f"\n{Fore.CYAN + Style.BRIGHT}{label}{Style.RESET_ALL}")
    print(json.dumps(data, indent=2, ensure_ascii=False))

def banner(text: str):
    print(f"\n{Fore.YELLOW + Style.BRIGHT}{'─'*55}")
    print(f"  {text}")
    print(f"{'─'*55}{Style.RESET_ALL}")

def hint(text: str):
    print(f"  {Fore.WHITE}{text}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────
COMMANDS = """
  ls                        — 列出所有 subscribers
  get   <supi>              — 取得 subscriber 詳細資料 (subscription profile)
  ue    [supi]              — 查詢目前已 register 的 UE context (AMF state)
  pdu   <smContextRef>      — 查詢 PDU session 詳細資訊
  demo                      — 執行 IPI-01 attack demo (呼叫 run_attack_demo.py)
  help                      — 顯示此說明
  exit                      — 離開
"""

def run_interactive(client: WebConsoleClient):
    print(f"""
{Fore.CYAN + Style.BRIGHT}
╔══════════════════════════════════════════════════════╗
║   Simple 5G NOC Agent — free5GC WebConsole CLI      ║
║   Mobile Network Security, Fall 2026                ║
╚══════════════════════════════════════════════════════╝
{Style.RESET_ALL}
  Mode: {Fore.GREEN}LIVE → {BASE_URL}{Style.RESET_ALL}
  直接呼叫 free5GC WebConsole REST API 進行管理操作。
{COMMANDS}""")

    while True:
        try:
            raw = input(f"{Fore.GREEN}noc> {Style.RESET_ALL}").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        # ── ls ──────────────────────────────────
        if cmd == "ls":
            banner("GET /api/subscriber  —  所有 subscribers")
            try:
                data = client.list_subscribers()
                if not data:
                    print("  (empty — no subscribers registered in free5GC)")
                else:
                    for s in data:
                        print(f"  • {Fore.CYAN}{s.get('ueId','?')}{Style.RESET_ALL}  plmnID={s.get('plmnID','?')}")
            except Exception as e:
                print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")

        # ── get <supi> ───────────────────────────
        elif cmd == "get":
            if not args:
                hint("用法: get imsi-208930000000001")
                continue
            supi = args[0]
            if not supi.startswith("imsi-"):
                supi = f"imsi-{supi}"
            banner(f"GET /api/subscriber/{supi}/{PLMN_ID}")
            try:
                data = client.get_subscriber(supi)
                if data:
                    pp("Subscription Profile:", data)
                else:
                    print(f"  {Fore.YELLOW}Subscriber {supi} not found{Style.RESET_ALL}")
            except Exception as e:
                print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")

        # ── ue [supi] ────────────────────────────
        elif cmd == "ue":
            supi = args[0] if args else ""
            path = f"/registered-ue-context/{supi}" if supi else "/registered-ue-context"
            banner(f"GET /api{path}  —  AMF registered UE context")
            try:
                data = client.get_registered_ue(supi)
                if not data:
                    print(f"  {Fore.YELLOW}No registered UE contexts found")
                    hint("→ 確認 UE 已透過 UERANSIM nr-ue 連上 free5GC")
                else:
                    for ue in (data if isinstance(data, list) else [data]):
                        print(f"\n  SUPI : {Fore.CYAN}{ue.get('supi','?')}{Style.RESET_ALL}")
                        print(f"  State: {ue.get('connectionState','?')}")
                        sessions = ue.get("pduSessionList", [])
                        if sessions:
                            print(f"  PDU Sessions:")
                            for s in sessions:
                                print(f"    id={s.get('pduSessionId')}  smContextRef={Fore.YELLOW}{s.get('smContextRef')}{Style.RESET_ALL}")
                        else:
                            print(f"  PDU Sessions: (none)")
            except Exception as e:
                print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")

        # ── pdu <smContextRef> ───────────────────
        elif cmd == "pdu":
            if not args:
                hint("用法: pdu <smContextRef>   (從 'ue' 指令的結果取得 smContextRef)")
                continue
            ref = args[0]
            banner(f"GET /api/ue-pdu-session-info/{ref}")
            try:
                data = client.get_pdu_session(ref)
                pp("PDU Session Info:", data)
            except Exception as e:
                print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")

        # ── demo ─────────────────────────────────
        elif cmd == "demo":
            banner("執行 IPI-01 Attack Demo (run_attack_demo.py)")
            import os
            project_root = os.path.dirname(os.path.abspath(__file__))
            subprocess.run(
                ["python3", "run_attack_demo.py", "--scenario", "IPI-01"],
                cwd=project_root,
            )

        # ── help ─────────────────────────────────
        elif cmd in ("help", "?", "h"):
            print(COMMANDS)

        # ── exit ─────────────────────────────────
        elif cmd in ("exit", "quit", "q"):
            print("Bye.")
            break

        else:
            print(f"  {Fore.YELLOW}未知指令: {cmd!r}  (輸入 help 看用法){Style.RESET_ALL}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    client = WebConsoleClient()
    if not client.login():
        sys.exit(1)
    run_interactive(client)


if __name__ == "__main__":
    main()
