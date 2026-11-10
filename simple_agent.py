#!/usr/bin/env python3
"""
simple_agent.py — 無需 API Key 的互動式 5G NOC Agent
=====================================================
直接透過 free5GC WebConsole REST API 操作。
不需要 LLM、不需要 API Key — 純 Python CLI。

使用方式:
    # free5GC 跑起來時（live mode）:
    python3 simple_agent.py

    # 不需要 free5GC（mock mode）:
    python3 simple_agent.py --mock

WebConsole API endpoints used:
    POST /api/login
    GET  /api/subscriber
    GET  /api/subscriber/:ueId/:servingPlmnId
    GET  /api/registered-ue-context
    GET  /api/registered-ue-context/:supi
    GET  /api/ue-pdu-session-info/:smContextRef
"""

import argparse
import json
import sys

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
BASE_URL   = "http://localhost:5000"
PLMN_ID    = "20893"
USERNAME   = "admin"
PASSWORD   = "free5gc"

# ─────────────────────────────────────────────
# Mock Data (used when --mock flag is set)
# ─────────────────────────────────────────────
MOCK_SUBSCRIBERS = [
    {"plmnID": "20893", "ueId": "imsi-208930000000001"},
    {"plmnID": "20893", "ueId": "imsi-208930000000002"},
]

MOCK_SUBSCRIBER_DETAIL = {
    "imsi-208930000000001": {
        "AuthenticationSubscription": {
            "authenticationMethod": "5G_AKA",
            "sequenceNumber": {"sqn": "000000000020"},
        },
        "AccessAndMobilitySubscriptionData": {
            "gprsSubscriptionData": None,
            "subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "2 Gbps"},
        },
        "SessionManagementSubscriptionData": [
            {
                "singleNssai": {"sst": 1, "sd": "010203"},
                "dnnConfigurations": {
                    "internet": {
                        "sessionAmbr": {"uplink": "200 Mbps", "downlink": "100 Mbps"},
                        "5gQosProfile": {"5qi": 9},
                    }
                },
            }
        ],
    },
    "imsi-208930000000002": {
        "AuthenticationSubscription": {"authenticationMethod": "5G_AKA"},
        "SessionManagementSubscriptionData": [
            {
                "singleNssai": {"sst": 1, "sd": "010203"},
                "dnnConfigurations": {
                    "ims": {"sessionAmbr": {"uplink": "50 Mbps", "downlink": "50 Mbps"}}
                },
            }
        ],
    },
}

MOCK_REGISTERED_UE = [
    {
        "supi": "imsi-208930000000001",
        "amfUeNgapId": 1,
        "ranUeNgapId": 1,
        "pduSessionList": [{"pduSessionId": 1, "smContextRef": "smctx-001"}],
        "connectionState": "CM-CONNECTED",
    }
]

MOCK_PDU_SESSION = {
    "smctx-001": {
        "pduSessionId": 1,
        "dnn": "internet",
        "snssai": {"sst": 1, "sd": "010203"},
        "pduSessionType": "IPV4",
        "sessionAmbr": {"uplink": "200 Mbps", "downlink": "100 Mbps"},
        "ueIpAddress": "10.60.0.1",
        "upfNodeId": "10.200.200.102",
        "sessionState": "Active",
    }
}

# ─────────────────────────────────────────────
# WebConsole Client
# ─────────────────────────────────────────────
class WebConsoleClient:
    def __init__(self, mock: bool = False):
        self.mock = mock
        self._token = ""

    def login(self) -> bool:
        if self.mock:
            self._token = "mock-token"
            print(f"{Fore.GREEN}[MOCK] Logged in as admin{Style.RESET_ALL}")
            return True
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
            print(f"  → 請先啟動 free5GC 或使用 --mock 模式")
            return False

    def _get(self, path: str):
        if self.mock:
            return None  # caller handles mock
        headers = {"Authorization": f"Bearer {self._token}"}
        r = requests.get(f"{BASE_URL}/api{path}", headers=headers, timeout=5)
        r.raise_for_status()
        return r.json()

    # ── Tool: list subscribers ──────────────────
    def list_subscribers(self):
        if self.mock:
            return MOCK_SUBSCRIBERS
        return self._get("/subscriber") or []

    # ── Tool: get subscriber detail ─────────────
    def get_subscriber(self, supi: str):
        bare = supi.replace("imsi-", "")
        if self.mock:
            return MOCK_SUBSCRIBER_DETAIL.get(supi) or MOCK_SUBSCRIBER_DETAIL.get(f"imsi-{bare}")
        return self._get(f"/subscriber/imsi-{bare}/{PLMN_ID}")

    # ── Tool: get registered UE context ─────────
    def get_registered_ue(self, supi: str = ""):
        if self.mock:
            if supi:
                return [u for u in MOCK_REGISTERED_UE if u["supi"] == supi]
            return MOCK_REGISTERED_UE
        path = f"/registered-ue-context/{supi}" if supi else "/registered-ue-context"
        return self._get(path) or []

    # ── Tool: get PDU session info ───────────────
    def get_pdu_session(self, sm_context_ref: str):
        if self.mock:
            return MOCK_PDU_SESSION.get(sm_context_ref, {"error": "smContextRef not found"})
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
  demo                      — 跑一遍完整的 IPI-01 attack demo (呼叫 run_attack_demo.py)
  help                      — 顯示此說明
  exit                      — 離開
"""

def run_interactive(client: WebConsoleClient, mock: bool):
    mode_label = f"{Fore.YELLOW}[MOCK]{Style.RESET_ALL}" if mock else f"{Fore.GREEN}[LIVE → {BASE_URL}]{Style.RESET_ALL}"
    print(f"""
{Fore.CYAN + Style.BRIGHT}
╔══════════════════════════════════════════════════════╗
║   Simple 5G NOC Agent — free5GC WebConsole CLI      ║
║   Mobile Network Security, Fall 2026                ║
╚══════════════════════════════════════════════════════╝
{Style.RESET_ALL}
  Mode: {mode_label}
  這是一個不需要 LLM API Key 的簡單互動 agent。
  它直接呼叫 free5GC WebConsole REST API。
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
                    if not mock:
                        hint("→ 確認 UE 已透過 nr-ue 連上 free5GC")
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
            import subprocess, os
            project_root = os.path.dirname(os.path.abspath(__file__))
            mode_flag = "--mock" if mock else "--llm"
            cmd_parts = ["python3", "run_attack_demo.py", "--scenario", "IPI-01", mode_flag]
            subprocess.run(cmd_parts, cwd=project_root)

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
    parser = argparse.ArgumentParser(description="Simple 5G NOC Agent — free5GC WebConsole CLI")
    parser.add_argument(
        "--mock", action="store_true",
        help="使用 mock 資料，不需要 free5GC 跑起來"
    )
    args = parser.parse_args()

    client = WebConsoleClient(mock=args.mock)
    if not client.login():
        sys.exit(1)

    run_interactive(client, mock=args.mock)


if __name__ == "__main__":
    main()
