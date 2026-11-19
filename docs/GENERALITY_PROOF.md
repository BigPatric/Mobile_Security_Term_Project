# Generality 證明 — 為什麼這個 gateway 不是「為三個攻擊寫死的程式」

**對象:** 評分老師、隊友。
**更新:** 2026-11-18
**關聯:** [../README.md](../README.md) · [DESIGN.md](DESIGN.md) · [END_TO_END_FLOW.md](END_TO_END_FLOW.md) · [RESULTS.md](RESULTS.md)
**全部證據都是離線、決定性的單元測試:** `python3 tests/test_generality.py`
(14 個測試;不需 live core、不需 testbed 大小)。

---

## 主張

Gateway 是一個 **policy-driven、procedure-aware 的 tool-call 檢查引擎**。
三個攻擊(ENUM-01 / DOS-01 / DOS-02)只是用來「展示它有效」的實驗;
它的價值在於**通用**——換 procedure、換 tool、換一個沒見過的攻擊,引擎不用改。

「通用」有三個各自獨立、可分別反駁的意思,分三個 stage 證明。每一條主張都對應
`tests/test_generality.py` 裡一個會跑的測試,**不是口頭宣稱**。

---

## Stage 1 — Composability:防護是「資料」,不是「程式」

**主張:** 對一個既有 tool 增加 / 移除 / 調整防護,是改 config,不是改 code。
同一個 `PolicyEngine` 類別、`gateway/` 底下一行都不改,只換 policy dict,
強制行為就不同。

| 測試 | 證明 |
|---|---|
| `test_no_builtin_cap_release_chain_without_rate_passes_bulk` | release chain 只放 `[identifier]` → 全部 session 被 bulk 釋放。**rate cap 不是內建的**:policy 沒寫,強制就沒有。 |
| `test_adding_a_rate_cap_is_pure_config` | 和上一條**唯一差別是三行 policy 資料** → bulk 被收斂到 2。 |
| `test_tuning_a_threshold_is_pure_config` | 同一條 policy,`max` 改成 1 / 3,cap 跟著變。沒有 code path 在選這個數字,是資料在選。 |
| `test_same_checks_guard_a_different_tool_by_config_only` | 把 `identifier + rate` 指到一個**讀取** tool(列舉節流)也成立。check code 完全沒提到 tool 名字。 |
| `test_two_tools_can_share_or_separate_budgets_by_config` | bucket 名稱是 config 字串:同名 → 兩個 tool 共用一個預算;不同名 → 各自獨立。 |

> 程式保證在 [gateway/checks/base.py](../gateway/checks/base.py):
> *「checks never filter by tool name themselves — WHICH checks apply to WHICH
> tool is decided by the policy config.」*

---

## Stage 2 — 跨 procedure 通用:fsm / rate 引擎不綁 PDU session

**主張:** 同一個引擎能強制它**沒有任何內建知識**的 procedure,只要把 procedure
宣告成資料(states / transitions / observe 規則)。

| 測試 | 證明 |
|---|---|
| `test_foreign_procedure_fsm_enforced_by_same_engine` | 一個**刻意非 5G** 的 `door_lock` procedure(LOCKED/UNLOCKED):未觀測前 unlock 被擋(`fsm-no-context`)→ 觀測 `read_doors` 學到 LOCKED → 准一次 unlock → 重複 unlock 被擋(`fsm-out-of-state`)。**這裡沒有任何 identifier(L1/L2 無意義、關閉),只有 L3 程序機制在跑,在一個它從沒見過的領域上。** 這是最決定性的「沒寫死」證明。 |
| `test_foreign_procedure_rate_cap_by_same_engine` | 守 PDU-release blast radius 的那個 `RateCheck`,原封不動地收斂 bulk 開門。rate limit 一點都不是 5G-specific。 |
| `test_foreign_procedure_full_cycle_lock_unlock` | 同一 procedure 的兩個 transition(unlock / lock)可組合循環,各由自己的 `FsmCheck` event 守。 |
| `test_second_5g_procedure_registration_lifecycle` | 第二個**真實 3GPP** procedure(TS 23.502 registration),不同 states(REGISTERED/DEREGISTERED)、不同 tool,全用 config 宣告。double-deregister 被當 out-of-state 擋,和 double PDU-release 完全對稱。 |
| `test_second_5g_procedure_rate_cap` | 另一個 procedure 上的 bulk deregistration DoS,由同一個 `RateCheck` 收斂。 |

> 這直接回答 advisor 問題 **B1**(「只有一個 procedure 容易被說成只是 rate limit」):
> procedure-aware 在**兩個真實 5G procedure + 一個完全外部 procedure** 上都成立。

---

## Stage 3 — Attack-blind 通用:擋的是「一類違規」,不是那三個攻擊

**主張:** 下面每個攻擊變體**都不是** ENUM-01 / DOS-01 / DOS-02,也**沒有**任何
check 是為它寫或調的——但既有的 fsm / rate / core_precheck 規則照樣擋下。
這證明 gateway 防的是「違反程序完整性這一類行為」,不是認得特定攻擊。

| 測試(未被腳本化的攻擊變體) | 被哪個通用規則擋 |
|---|---|
| `test_unscripted_release_of_never_seen_session_blocked_by_fsm` | 釋放一個從沒被 query 過的 session → FSM:從 UNKNOWN 不是合法 transition(`fsm-no-context`)。 |
| `test_unscripted_target_a_nonexistent_session_blocked_by_core_precheck` | 語法正確但指向**不存在**的 PDU session id → `core_precheck` 直接問 core,拒絕(`core-precheck-failed`);release 從未送達 core。 |
| `test_unscripted_forged_auth_bulk_on_a_different_procedure_still_capped` | **DOS-02 的洞搬到一個我們沒寫過攻擊的 procedure**(UE deregistration):每筆都帶偽造的 `operator_authorization`,`rate`(`exempt_authorized: false`)仍收斂 bulk。**授權騙得過 provenance,騙不過程序狀態 / 數量對帳。** |
| `test_unscripted_replay_after_legit_release_blocked_by_fsm` | 合法 release 後重放同一筆呼叫 → FSM 已 commit RELEASED,重放即 out-of-state;無任何 replay 專屬邏輯。 |

---

## 誠實界線(報告要寫)

- **「純 config」只限於保護邏輯。** fsm / rate / provenance / core_precheck 完全不用改。
  但要讓 agent 能呼叫一個**新的 core 操作**(例如真的 establishment / deregistration),
  需要在 `free5gc_tools/` 加一個薄 tool adapter。
  → 這個解耦本身就是架構 general 的定義:**擴充保護範圍 = 改 config;接入新 core 操作 = 加一個 tool adapter。**
- **Rate 是 bound-the-blast-radius,不是 0。** cap 之前那幾筆仍會過;刻意壓在視窗下的
  slow-drip 不被 rate 擋(這是 rate limiting 的本質)。但 FSM 的順序違規是**全擋**
  (double / out-of-state release = 0 通過),兩者互補。
- 這些是**離線決定性**證明(引擎邏輯 general)。live testbed 的量化 ASR/FP/latency
  見 [RESULTS.md](RESULTS.md)。

---

## 一句話

> 換一個 procedure、換一個 tool、換一個我們沒想過的攻擊,**gateway 的程式都不用動**——
> 要改的只有 policy 資料。這就是 general。
