# Final Report Revision Plan

依據 2026-11-23 對 `latex/main.tex` 的 review，整理出可以補做的事。
每項標註 **[VM]**（需要 free5GC 測試環境）或 **[本機]**（只改文字或程式碼）。

建議順序：A → B → C，D/E 視時間而定。

## 進度（2026-11-22）
- A1 ✅ `results/attack_evidence_live.jsonl` 已加入；重新產生的 CSV 與原本完全相同。
- A2 ✅ 採方案 1：Table III（現在編號為 IV）改用 pooled 數字；first pass（`head -26`）放內文。
- A3 ⏭ 不做（示意圖，圖說已註明來自較早的 testbed）。
- A4 ✅ 原因：有 1–2 個 UE 在攻擊開始時仍是 DEREGISTERED；369 個未被擋的 release 全數通過
  post-condition。各格範圍寫在 Fig. 3 圖說。
- A5 ✅ 用詞修正完成，並補引 AgentDojo、InjecAgent。
- B ✅ 完成；ENUM-01 重跑 leakage 0.00（所有含 L1 的模式）。
- C ✅ 完成；DOS-02 在 L1+L2 與 full 下 0 sessions，BENIGN-02/04 FP 0.00。報告 `\tbd` 已全部填入。
- 重跑指令：`sudo REPEATS=5 PRESET=signed ./tools/run_live_matrix.sh`（只跑受影響的 8 格 × 5 = 40 次；
  沒有改變 core 狀態的 run 之後沿用同一個 core）。
- D ⏭ 不做。
- E ✅ 寫進 Sec. VI future work。

---

## A. 低成本、論述修正（必做）

### A1. [VM] 把 evidence log 放進 repo
- 問題：`attack_evidence.jsonl` 被 `.gitignore` 排除，讀者無法驗證
  「aggregate script 只做算術」這句話。
- 做法：
  ```bash
  cp attack_evidence.jsonl results/attack_evidence_live.jsonl
  git add -f results/attack_evidence_live.jsonl
  python3 tools/aggregate.py --csv results/results results/attack_evidence_live.jsonl
  ```
- 確認重新產生的 CSV 和目前 `results/*.csv` 一致。

### A2. [VM → 本機] Latency 表格改用可重現的數字
- 問題：Table III 用「first pass」，但 repo 的 `results/results_latency.csv` 是
  pooled 結果，兩者差很多：

  | Mode | first pass p95（報告） | pooled p95（CSV） |
  |---|---|---|
  | L1+L3 | 23.3 ms | 97.7 ms |
  | Full  | 0.092 ms | 65.6 ms |

  另外，內文寫「median 介於 0.02–0.08 ms」，但 L1 的 p50 是 0.083（first pass）和
  0.095（pooled），超出這個範圍。
- 做法（二擇一）：
  1. 主表改用 pooled 數字，first pass 改放在內文當補充。
  2. 把 first pass 的 evidence 也另存一份並 commit（例如
     `results/attack_evidence_pass1.jsonl`），再用 `aggregate.py` 產生
     `results/results_latency_pass1.csv`。
- 修正「0.02 and 0.08\,ms」的範圍，改成和表格一致。

### A3. [VM] 用 9 UE testbed 重截 Fig. 5（DOS-02 trace）
- 問題：目前的圖來自較早、較小的 testbed，和主結果不是同一個環境。
- 做法：9 UE 下各跑一次 `DOS-02 --gateway on --layers L1,L2` 與
  `DOS-02 --gateway on`，截圖取代 `latex/figures/tex_dos02_l1l2.png`、
  `tex_dos02_full.png`，並刪掉圖說最後一句「Trace shown from an earlier
  smaller-testbed run…」。

### A4. [VM] 解釋為什麼無防禦時 release 不到 9 個
- 問題：off/RBAC 下平均只 release 8.0–8.8 個，代表有 release 的 post-condition
  失敗。只寫「testbed variation」不夠，這會影響 ground truth 的可信度。
- 做法：從 evidence 找出那些失敗的 release，看失敗原因（timeout？SM context 查不到？
  UE 沒成功建立 session？），寫進 Sec. V-B。
- 同時在 Table II 或 Fig. 3 補上每格的 min/max（或標準差）。

### A5. [本機] 修正論述用詞
- **Threat model goal (ii)**（Sec. II-C）：改成「no state change is driven by untrusted
  content without an authorization *claim*」，並說明在 agent 會照抄假 ticket 的前提下，
  L2 只對不偽造 ticket 的 injection 有效。（若完成 C，則改回原句。）
- **Ablation 結論**（Sec. V-B「Removing any layer lets some attack through…」）：
  說明這句只對非適應性攻擊者成立；一個總是偽造 ticket 的攻擊者會讓 L2 失效。
- **Scripted agent**（Sec. VI）：「a real model can only be hijacked less often」改成
  「ASR 是在 scripted agent 所涵蓋的 action space 下的上界」，並說明真實模型可能使用
  不同工具、參數或節奏。
- **Related work**：「To our knowledge, no prior work…」限定在「3GPP procedure state」
  範圍內；補引用 AgentDojo、InjecAgent 等 prompt-injection benchmark。

---

## B. [本機 + VM] Token 改用 keyed HMAC（中成本、建議做）

- 問題：Sec. VI 承認 token 是未加鹽 SHA-1 前綴，可被離線窮舉。
- 程式：`gateway/tokenizer.py:67` 改成 `hmac.new(secret, canon, sha256)`，secret 由
  gateway 啟動時產生或從 config / 環境變數讀取（不進 repo）。
- 測試：更新 `tests/test_tokenizer.py`，加一個「沒有 secret 就無法從 SUPI 算出 token」的測試。
- [VM] 重跑 ENUM-01（所有模式 × 5 次），確認 leakage 結果不變。
- 報告：刪掉或改寫 Sec. VI「Token derivation」段落與 Sec. III-B 的括號註記。

---

## C. [本機 + VM] L2 驗證 signed authorization（中成本、效果最大）

- 問題：L2 只檢查 `operator_authorization` 是否非空
  （`gateway/taint_tracker.py:109`、`gateway/checks/base.py:37`），所以任何偽造字串都能通過。
- 設計：gateway 簽發 capability token = HMAC(secret, procedure | max_count | expiry |
  nonce)，只透過 trusted operator task 路徑交給 agent。L2 驗證簽章、procedure、有效期限
  與次數。
- 測試：
  - 偽造字串 → 被 L2 擋下。
  - 正確 token → 通過；超過 max_count → 被擋下。
  - token 過期或 replay → 被擋下。
- [VM] 重跑 DOS-02 與 BENIGN-02/04（所有模式 × 5 次）。預期 L1+L2 下 DOS-02 變成 0
  sessions，BENIGN 仍為 FP 0。
- 報告：更新 Table II、Fig. 3、Sec. III-C、Sec. VI「Authorization is an in-band claim」、
  Abstract 與 Conclusion。保留「舊版 L2」結果作為對照，說明 taint laundering 如何被解決。

---

## D. [VM] 會碰到 rate cap 的 benign bulk maintenance live run（選做）

- 問題：4 個 benign task 都只 release ≤1 個 session，FP=0 的證據很薄。
- 做法：新增 BENIGN-05（authorized 釋放 5 個 session）放進 `benchmark/benign/`，
  在 full gateway × 5 次下跑，預期會被 rate cap 擋（FP），用 live 數據支持 Fig. 6 的
  trade-off。

## E. [VM] 小規模真實 LLM 實驗（選做、成本最高）

- 問題：題目是 LLM agent，但全部用 scripted agent，是最大的空白。
- 做法：接一個真實模型，DOS-01/DOS-02 × {off, full} × 5 次，回報真實 ASR 和
  gateway 擋下的比例。
- 若沒做，在 Sec. VI 明確寫為 future work（目前已部分提到）。

---

## 完成後的檢查清單
- [ ] `results/` 的 CSV 都由 commit 進來的 jsonl 重新產生
- [ ] Abstract、Conclusion、README 的數字和新表格一致
- [ ] 測試全數通過，更新內文的測試數量（目前 62）
- [ ] 重新編譯 `final_report.pdf`
