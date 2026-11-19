# 自適應攻擊者 — 防禦的邊界分析

**對象:** 評分老師、隊友。
**更新:** 2026-11-19
**證據:** `python3 tests/test_adversarial.py`(5 個離線、決定性、時間可控的測試,全過)。
**關聯:** [RESULTS.md](RESULTS.md) · [GENERALITY_PROOF.md](GENERALITY_PROOF.md) · [END_TO_END_FLOW.md](END_TO_END_FLOW.md)

三個 demo 攻擊都是「現在就做壞事」的一次性攻擊。真實攻擊者會**適應**。這份文件讓攻擊者
適應(spread、forge、reorder、換 bucket),並**誠實記錄每一種是被擋、還是擋不住** ——
重點不是「全擋」,而是一條**精確的邊界**。時間用注入的假時鐘模擬,所以「慢速」不需真的等,
結果決定性。

---

## 結果矩陣

| 攻擊變體 | 結果 | 被哪個機制決定 | 測試 |
|---|---|---|---|
| 爆量 bulk teardown | ✅ **擋**(收斂到 cap) | L3 rate(bound blast radius) | `test_burst_bulk_is_capped_by_rate` |
| 偽造授權的爆量 | ✅ **擋** | L3 rate(忽略授權宣稱) | `test_forged_auth_burst_still_capped_by_rate` |
| double / out-of-state release(慢速) | ✅ **擋**(與時間無關) | L3 FSM 順序 | `test_slow_drip_double_release_still_blocked_by_fsm` |
| **slow-drip:跨不同 session、拉長到 rate 視窗外** | ❌ **擋不住(residual risk)** | windowed rate 看不到 | `test_slow_drip_across_distinct_sessions_evades_rate` |
| **分散到不同 rate bucket** | ❌ **擋不住(config 決定)** | 各 bucket 各自預算 | `test_separate_buckets_let_an_attacker_double_the_budget` |

---

## 結論(可寫進報告 / abstract)

1. **Rate limiting 收斂的是「爆量」,不是「持續低速濫用」。**
   把 release 拉長到視窗外、且每筆都打**不同的、確實 ACTIVE 的 session**,就沒有任何 out-of-state
   可抓,windowed rate 也看不到 → 全數通過。這是 rate 的**本質上限**,不是 bug。

2. **FSM 順序約束與時間無關,不可用 slow-drip 規避。**
   double / out-of-state release 無論何時發生都非法 → slow-drip 對它無效。

3. **因此防禦的真正下限是「程序狀態一致性(FSM)」,不是速率。**
   偽造授權騙得過 provenance(L2),騙不過 rate/FSM(L3);slow-drip 規避得了 rate,規避不了 FSM。
   兩種可規避性正交 —— 這正是「縱深防禦:來源完整性 ⟂ 程序完整性」的實證。

4. **Bucket 粒度是一個明確的 policy 取捨。** 把所有 teardown 類操作綁同一個 bucket 可關掉
   「分散刷不同 bucket」的洞;分開則不行。這在 config 層一行決定,不是 code 問題。

---

## Residual risk → future work(誠實列出)

- **跨 session 的 slow-drip**:需要一個**累計 / 絕對預算**(例如「每 N 分鐘全域最多釋放 M 條」,
  或對「短時間內釋放比例異常」做偵測),補 windowed rate 的盲區。
- **bucket 分散**:把語意相近的 high-risk sink 歸入同一 teardown bucket。
- 兩者都是在既有 policy pipeline 上**加規則 / 調 config**,不改引擎 —— 與 [GENERALITY_PROOF.md](GENERALITY_PROOF.md) 的論點一致。

> 一句話:**本防禦可證明地收斂「爆量」與「亂序」攻擊,並明確界定其對「持續低速 / 分散」攻擊的
> 邊界;真正關不掉的底線是程序狀態一致性。** 誠實標出邊界,比宣稱「全擋」更有份量。
