# 量化評估 — ASR / FP 取捨曲線(合成測資)

**對象:** 評分老師、隊友。
**更新:** 2026-11-19
**產生:** `python3 tools/eval_curve.py`;測資 [../benchmark/generator.py](../benchmark/generator.py);harness 自我檢查 `python3 tests/test_generator.py`(5/5 過)。
**關聯:** [RESULTS.md](RESULTS.md)(live 單點)· [ADVERSARIAL_BOUNDARY.md](ADVERSARIAL_BOUNDARY.md)(邊界)

把 ASR / FP 從「三個手寫個案」升級成「掃一條曲線」。[generator.py](../benchmark/generator.py) 產出
16 條帶 **intent 標籤** 的 trace(善/惡、含最難的「合法大量維運」),[eval_curve.py](../tools/eval_curve.py)
把每條 trace 用**真實 PolicyEngine** 對假核心重放,在一串 rate cap 上量「攻擊效果 vs 誤擋」。
**產生器不知道 gateway 的門檻值** —— 指標是量出來的,不是假設的(評估不自己考自己)。

> 方法註:bulk teardown 在**trace 層級**是惡意的,但每一筆 release 單看都是 3GPP 合法操作。
> 所以 rate 擋的是「合法但過量」的呼叫 —— 指標因此定在**效果**(惡意 trace 真的拆了幾條)與
> **false positive**(合法 trace 是否被擋),隨門檻掃動量測。此曲線隔離 L3(identifier+fsm+rate);
> L1/L2 正交,見 [RESULTS.md](RESULTS.md) 的 ablation。

---

## 結果:rate cap 掃描(ALLOWED_BLAST=1,window=60s)

| cap | ASR | 平均釋放比例 | 單次最多釋放 | slow-drip | out-of-state 全擋 | **FP rate** |
|---|---|---|---|---|---|---|
| 1 | 0.40 | 0.53 | 8 | 13/13 | ✅ | **0.50** |
| 2 | 1.00 | 0.66 | 8 | 13/13 | ✅ | 0.38 |
| 3 | 1.00 | 0.80 | 8 | 13/13 | ✅ | 0.25 |
| 5 | 1.00 | 0.93 | 8 | 13/13 | ✅ | 0.12 |
| 8 | 1.00 | 1.00 | 8 | 13/13 | ✅ | **0.00** |
| ∞ | 1.00 | 1.00 | 8 | 13/13 | ✅ | 0.00 |

---

## 結論(可寫進報告)

1. **存在明確的 ASR–FP 取捨,且有 knee。** cap 調低 → 攻擊釋放變少(平均釋放比例 1.00→0.53),
   但 **FP 上升**(0.00→0.50),因為合法的大量維運被一起擋掉。cap 調高則相反。
   **rate 無法區分「合法大量」與「惡意大量」**(兩者都帶授權、都不帶污染)—— 這是取捨的根因。

2. **slow-drip 在每個 cap 都 13/13 全過** —— windowed rate 的本質盲區(與 [ADVERSARIAL_BOUNDARY.md](ADVERSARIAL_BOUNDARY.md) 一致)。

3. **out-of-state 在每個 cap 都全擋** —— FSM 順序約束與門檻無關。

4. 合起來:**rate cap 是一個「可調的 blast-radius 旋鈕」,但它的兩端都有代價(漏過 / 誤擋),
   且對 slow-drip 無效;真正與門檻無關、不可規避的保證來自 FSM 的程序順序。**
   → 若要同時壓低 ASR 與 FP,不能只靠調 rate;需要能分辨「合法大量 vs 惡意大量」的訊號
   (例如可驗證的簽章式授權,或累計/異常偵測)—— 列為 future work。

---

## 誠實限制
- 合成 workload 不等於真流量;宣稱的是「在受控、有 ground-truth intent 標籤的 workload 下」的曲線。
- 曲線隔離 L3;完整三層的 live 單點結果見 [RESULTS.md](RESULTS.md)。
- 重放用假核心(決定性、時間可注入);這量測的是**強制邏輯**,不是核心效能。
