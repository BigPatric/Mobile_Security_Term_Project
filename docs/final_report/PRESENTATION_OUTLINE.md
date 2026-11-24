# Final Report — What to Present (planning outline)

**用途:** 期末報告 `docs/final_report/latex/main.tex` 要呈現的內容清單與定位決策。
先在這裡對齊「宣稱 ↔ 證據 ↔ live/offline」,再去改 LaTeX。
**狀態日期:** 2026-11-25 ·  資料來源:`results/tables/main_*.csv`、`results/evidence/*.jsonl`

---

## 0. 一句話定位(title 已定,L3 命名待老師確認 Q3)

> A **Provenance-Aware, Core-Grounded** Secure MCP Gateway for an LLM agent acting
> on the core network — decisions and evaluation are both anchored in the core's
> real state. L1+L2 stop the attacks live; L3 is a secret-independent,
> **procedure-aware** fallback whose core-grounded precheck and rate cap are now
> both demonstrated on the live core.

- 標題維持現狀(`main.tex:53` 已是 Provenance-Aware, Core-Grounded,本來就沒有 Procedure-Aware)。
- **保留** L3「procedure-aware verifier」名稱,但誠實標註每個子檢查的驗證狀態:
  - core_precheck → **live**(DOS-03)
  - rate cap → **live**(L2 失效模式)
  - FSM 純順序防護 → **offline**(對 free5GC release 冗餘;有害亂序需 establishment tool 才能 live → future work)

---

## 1. 系統(Design)— 不變

三層 gateway 架在 agent↔核網工具之間:
- **L1** 識別碼 token 化(SUPI opacity)
- **L2** taint 追蹤 + gateway 自簽 capability(signed,取代舊的 claim-only)
- **L3** rate cap + **core_precheck**(核網真實狀態)+ procedure FSM

跑在真實 free5GC v4.1.0 + UERANSIM(9 UE),攻擊由「必定被劫持的腳本化 agent」
經被注入的 alert log 發動。保護力是**資料(policy),不是程式碼**(見 generality)。

---

## 2. 威脅模型(要補的假設,Q4)

- **攻擊者可觀察 agent 輸出** —— agent 把結果寫回監控/工單系統,攻擊者本就能在那裡讀寫。
  有此假設,ENUM 的「SUPI 外洩」即成立,不必另做對外傳送工具。(limitations 註明是假設)
- **注入路徑是假設的**(B1):未展示具體 5G 可控欄位會流進 alert log。
- **release 走非標準路徑**(B2):tool 直打 SMF ReleaseSMContext,跳過 N1/N2;真實 OAM 較可能走 MnS/NEF → future work。
- **腳本化 agent = 最壞情況上界**(B3):agent 必定被劫持、攻擊從不拿 capability;
  數字是「腳本動作空間內的上界」,非真實 LLM 攻擊成功率 → live LLM 列 future work。

---

## 3. 評估結果(Evaluation)— ground truth,SMF 204 + probe 404 雙重確認

### 3.1 攻擊有效性(ENUM-01 / DOS-01 / DOS-02,每格 5 repeats)
| 層級 | ASR | leakage | DOS 平均拆除 |
|---|---|---|---|
| off / rbac | 0.67 | 1.00 | ~9 |
| L1 | 0.67 | **0** | ~8 |
| L1+L2 / full | **0** | 0 | **0** |
| L1+L3 | 0.67 | 0 | 3(rate cap) |
| full, claim-only L2 | — | 0 | 3(偽造 ticket 被 L2 放行,只剩 L3 壓) |

> **注意:ASR 表只放 ENUM/DOS-01/DOS-02。** DOS-03 不併入(見 3.2):它即使無防禦
> 也拆 0(目標 session 不存在),併入會把 off 的 ASR 從 0.67 稀釋成 0.50,失真。

### 3.2 DOS-03 — core_precheck 的 live 證據(**A2 新增,獨立呈現**)
注入 log 指名「release PDU session 7」(testbed 只有 session 1)。agent 照指名 id
直接下手、不先 query 確認 → 只有自己查核網的 core_precheck 能擋。

| mode | released | 擋在哪 |
|---|---|---|
| off | 0 | 未擋,release 送到 SMF → no-op(無此 session) |
| **L1+L3** | **0** | **L3 / core-precheck-failed(真 core 上 live 擋下)** |
| L1+L2+L3 | 0 | L2 / taint-control-flow(full stack 更早擋) |

5/5,全部 real core。**這補上了「core_precheck 從沒在真 core 上擋下」的缺口。**

### 3.3 Ablation 歸因(哪一層擋下)
- DOS-01/02:L1+L2 → L2;L1+L3 → L3 rate;full → L2。
- DOS-03:L1+L3 → **L3 core_precheck**;full → L2。

### 3.4 誤擋(5 benign tasks × 5)
- 單筆操作 0 誤擋(BENIGN-01~04)。
- 唯一誤擋:合法批次清空(BENIGN-05),full 下 FP 5/5(rate cap 綁授權者,分不出合法 vs 惡意批次)→ 已知取捨。

### 3.5 成本(latency)
- gateway 自身檢查 < 0.6 ms(含所有被擋的 release)。
- 轉送 release 付一次核網往返:latency rerun(乾淨 WebConsole)median **13 ms**、p95 18 ms。
- DOS-03 L1+L3 的 precheck 往返(矩陣用的共用 WebConsole):median ~18 ms,一次冷啟 49 ms outlier;與 13 ms 一致、都遠在 50 ms 設計目標內。
- WebConsole 記憶體洩漏曾讓 precheck 從 ~20 ms 漂到 90–479 ms → 已改成每次重啟 WebConsole 取乾淨值。

---

## 4. L3 到底提供什麼(講清楚,避免「只有 offline」誤導)

| L3 子檢查 | live 狀態 | 說明 |
|---|---|---|
| rate cap | **live**(L2 失效模式) | 偽造 ticket DoS 8.4→3;綁所有呼叫者 |
| core_precheck | **live(A2 已補)** | DOS-03 L1+L3 真 core 擋下不存在 session |
| FSM(順序) | **offline-only** | 對 free5GC release 冗餘(SMF 本就 404);通用性靠 offline+原始碼證據 |

一句話:L3 = 不依賴 secret、綁所有呼叫者的後備層;rate cap 與 core_precheck 都有 live 證據,
純順序防護(FSM)的必要性以可重現 offline 測試呈現。

---

## 5. 通用性(Generality)— offline,但決定性

同一 PolicyEngine 僅靠 config 就能守:
- 第二個真 3GPP procedure(UE 去註冊)
- 一個非 5G procedure(門鎖)
零改碼 → 不是三條硬編碼規則,是 policy-driven 的 class-level 防禦。

---

## 6. Limitations(誠實列,對應 devices.txt C/B)

- **C1** 有效 capability 完全跳過 L2(連 value-level taint)→ 靠 L3 rate/precheck 當後備。
- **C2** rate cap 誤擋合法批次(BENIGN-05)。
- **C3** slow drip / bucket split 可繞過 windowed rate cap → cumulative budget 列 future work。
- **C4** token 為 HMAC 16-bit 前綴,猜中機率 ~N/2^16;猜中不洩漏 SUPI。
- **B1/B2/B3** 見 §2(注入路徑假設、release 非標準路徑、腳本 agent 上界)。
- **FSM** 對 free5GC release 冗餘,通用性論證在 offline(§4)。
- shared-session state、去 token 化範圍:offline 覆蓋(live 單一 session)。
- OAuth 關閉(與 agent→core 防護正交);DOS-02 截圖來自較早 3-UE claim-only 版。

---

## 7. 收尾待辦對照(devices.txt)

| 項目 | 狀態 |
|---|---|
| A2 core_precheck live 擋下 | ✅ 已 live 證實(DOS-03) |
| A1+B 威脅模型假設 | 寫作(§2) |
| A3 FSM release 冗餘誠實標示 | 寫作(§4/§6) |
| A4 真 capability 濫用 live | offline + 標示(有餘力補 live run) |
| C1–C4 殘餘限制 | 寫進 §6 |
