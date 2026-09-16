# qos_manager 第一版實作計畫

更新日期：2026-09-15。目標專案：`go-upf-flowqos`。

步驟 1–3 已改為直接更新 policy。移除 Constraint graph、QER 副本、反向引用表、graph diff、Plan/Commit/Abort、Snapshot 與 constraint ID registry。使用者目前不需要 QoS rollback；不另外建立該機制。既有 forwarder 的 rollback 保持原樣。

步驟 4 的正式 PFCP 接線已完成，使用方式見 [QoS 與 PFCP 整合](qos_pfcp.md)。TC/BPF enforcement 尚未實作。SMF 本地修正基線為 `fix/ambr-qer-omit-qfi`，包含 `d4e6a00`、`c2f8a69`；不據此假定 testbed 已部署。

步驟 5-2 的 [Set/Clear binding 接線](qos_binding.md) 已完成程式與編譯／單元驗證，kernel 與封包聯測待做。classid 統一由未來的 N6/N3 出口 BPF 設定。

## 1. 第一版的目標與邊界

沿用現有 RuleChangeSet、RuleState 及 PDR.QERIDs，manager 只管理 PDR 對應的 policy。MBR、GBR、Gate、CorrelationID 等仍由既有 QERConfig 保存、解析、合併及下發。

- V1-A：policy 更新、診斷、PFCP 接線與清理。
- V1-B：PDR binding、TC/BPF、共享 QER runtime state、多 MBR EDT 與實測。
- GBR 保留既有欄位；cap-only backend 不提供 GBR 最低頻寬保證。
- 出口/slice/class 使用明確 mapping，方向只使用 PDR Source Interface。

## 2. 已確認的現況

| 元件 | 已有能力 | 第一版沿用方式 |
|---|---|---|
| `internal/rules/rules.go` | PDR.QERIDs、方向資訊、FAR、QER 的 GBR/MBR/gate/QFI/CorrelationID | 保持 PFCP 輸入模型；不另建可獨立修改的 PDR database |
| `internal/pfcp/rule_state.go` | PDR/QER/FAR 查詢、RangePDR、合併後的唯讀候選狀態 | 直接實作 Translator 所需 RuleView |
| `internal/pfcp/rule_apply.go` | 驗證、執行、成功後 commit | 作為 QoS 與 forwarding 的協調入口 |
| `internal/forwarder` | 私有 netlink plan、applied snapshot、補償與 session cleanup | 保留 netlink ownership，增加 binding 編碼與清理協調 |
| `go-gtp5gnl/flow_qos.go` | PDR_FLOW_QOS 編解碼、Set/Clear 所需 ABI | 使用修改版依賴，無須另創 QoS netlink command |
| `roundspring2003-gtp5g` | PDR binding 與 skb marking 程式碼 | 必須確認實際載入版本及出口標記保留 |

`bfd7bb4` 的 Set/ClearFlowQoSBinding 是可參考的編碼 helper；當時呼叫者只有測試。目前工作區已重構為私有 forwarder plan，應移植編碼能力，不能整份恢復舊 plan 介面。

### 2.1 修正後的 SMF 基線

`smf` 的修正已把 QER.QFI 改成 optional pointer，並涵蓋：

- 一般與 dual-connectivity datapath 建立的共享 Session-AMBR QER：保留 GateStatus/MBR，不設定 QFI。
- default/其他 flow QER：保留原本明確指定的 QFI。
- PFCP `qerToCreateQER()`：QFI 為 nil 時省略整個 QFI IE，不送 QFI=0；Establishment 與 Modification 中新增 QER 都走此 helper。
- NGAP modify-confirm：略過沒有 QFI 的 QER。

修正時已通過 SMF `go build ./...`、`go test ./...` 與 PFCP TLV round-trip、兩種 datapath、NGAP regression tests；尚無本次修正的實際 SMF/UPF 連線驗收結果。

第一版不再加入「AMBR QER 也帶 default QFI」的相容 adapter，也不透過 QFI=1、引用順序或取第一個 QER 來選 marking 值。AMBR 的共享 MBR 語意與 flow marking 分開處理。

**QFI 缺失只表示該 QER 不提供 QFI marking 指令，不足以證明它就是 Session-AMBR。** 其他 gate-only/rate-only QER 也可以沒有 QFI；即使 QER 有 QFI，其 MBR/gate 仍須正常處理。後續 backend 依既有 QER 欄位與 PDR 引用執行限速，不必先替每個 QER 猜一個 AMBR/flow 角色。Session-AMBR fixture 由已知 SMF 配置確定，只關聯 non-GBR flows。

### 2.2 kernel 仍需處理的能力差異

本地 `roundspring2003-gtp5g/src/genl/genl_pdr.c`：

- gate 會遍歷所有 QER，只要有 CLOSED 就關閉對應方向。
- `qer_with_rate` 是單一 pointer，迴圈會以符合條件的 QER 覆寫它；不是多個 rate 都執行。
- `set_pdr_qfi()` 仍存在優先非 1 QFI 的舊邏輯。新規劃先驗證引用集合只有一個一致的非空 QFI，不能依賴此 heuristic 消解衝突；需要實測 QER-only 更新、刪除後 cached QFI 是否正確刷新。

因此 SMF 修正解決的是多 QER 的 marking 歧義；`qer_with_rate` 的單一 policer 限制仍存在。當下發多個適用 rate QER 時需處理全部限制；具體 EDT/排程算法依 §7.2.1 留待決定，不代表每個 PDR 必須有多個 rate QER。

### 2.3 testbed 前置驗證

1. 使用含 `d4e6a00`（原 `0313c25` 重套後）修正的 SMF binary，記錄 UPF、go-gtp5gnl 與 gtp5g 版本。
2. 建立全新的測試 PFCP session，確認 AMBR QER 無 QFI IE、flow QER 有正確 QFI，PDR 同時引用兩者。
3. 不假定更新舊 QER 時省略 QFI 就會清除舊值：Update QER 缺欄位代表不改變。第一版採重建測試 session 的遷移方式，不加入熱遷移舊 AMBR QFI 的相容邏輯。
4. 驗證 UL/DL rate 引用與 DL GTP-U QFI；此檢查獨立於 skb mark/priority。


## 3. 核心模型：policy 沿用 QER 引用

```text
PFCP Session 10
  PDR 11.QERIDs = [7, 9] -> Policy 11.QERIDs = [7, 9]
  PDR 12.QERIDs = [8, 9] -> Policy 12.QERIDs = [8, 9]

MBR/GBR/Gate/QFI 的完整設定：仍在 Session/RuleState 的 QERConfig
Policy：Key、PolicyID、Direction、Target、QERIDs、QFI 摘要/來源、Diagnostics
```

Policy 保留 QER IDs 作為衍生 binding 所需引用，不複製完整 PDR 或 QER。沒有 Constraint、ReferencedBy 或另一個 QER database。全部 QER 引用保留並排序去重，不只取第一個 QER。

- PDRKey = (LocalSEID, PDRID)。PolicyID 為全 UPF 本地 24-bit 數字，與 QFI/QERID 無關。
- 同一 PDR 更新保留 PolicyID；移除後暫不重用數字。只有一個遞增 counter，沒有另一套資源 reservation registry。
- 未來共享 rate runtime 可用 (LocalSEID, QERID, Direction) 識別。不同 session、不同方向分開；相同 key 不可按 PDR/CPU/出口拆成多份額度。
- 目前尚未建立上述 runtime map，亦無 constraint numeric ID。

## 4. 更新分工

| 請求 | manager 動作 |
|---|---|
| CreatePDR | 從 RuleState.PDR(id) 讀完整資料，新增 policy |
| UpdatePDR | 只更新自己的 policy，包括方向、引用及 QFI 摘要 |
| RemovePDR | 刪除該 policy；不刪除原始 QER |
| UpdateQER 含 QFI | 掃描候選 PDR.QERIDs，刷新引用者的 QFI 摘要 |
| UpdateQER 只有 MBR/GBR/Gate 等 | 不刷新 policy；設定仍走既有 QER 下發流程 |
| Create/RemoveQER | 原始規則由 PFCP 管理；有引用變更時透過同次 PDR 操作反映 |
| FAR/URR 或空變更 | 不產生 policy 操作 |

未來 rate backend 直接讀取同一份 RuleChangeSet 與合併後 QER 更新共享設定，不能把「policy Changes 為空」誤解成沒有 QER 更新。

QFI 衝突仍保留 AmbiguousQFI，policy.QFI 為 nil；不依第一個/最後一個或非 1 heuristic 選值。QFI-only/gate-only QER 僅作為普通 QER 引用，不為它建立虛構的限速物件。

驗證及 patch 合併由既有 PFCP 層負責；manager 的 lookup error 只防止已驗證 view 失效。明確 Update 即使值相同也更新，不做相等比較。僅 QFI 更新需要掃描引用，PDR-only 操作直接查 ID。

## 5. 記憶體與檔案

| 所有者 | 保存內容 |
|---|---|
| Session / RuleState | 完整 PDR/QER 及既有引用驗證、合併結果 |
| Manager | map[PDRKey]Policy、下一個 PolicyID |
| 未來 BPF backend | 共享 QER 設定及各方向 runtime state；layout 待定 |

```text
internal/rules/qos.go              # 共用 policy/key/target/diagnostic
internal/qos_manager/types.go      # 沿用 PDR/QER/RangePDR 的 RuleView
internal/qos_manager/changes.go    # RuleChangeSet -> policy 操作清單
internal/qos_manager/translator.go # 單一 PDR -> policy metadata
internal/qos_manager/resolver.go   # Source Interface -> UL/DL
internal/qos_manager/manager.go    # Apply、Policy/Policies、RemoveSession
```

Manager 沒有 graph/history/pending plan。Apply 完成即更新當前記憶體。Policy/Policies 查詢複製少量 slice/pointer，避免呼叫者改壞 manager 內容；這不是 rollback snapshot。建立輸出與檢查 ID 容量在記憶體修改前完成，錯誤不留下半份本地 policy 更新。

## 6. PFCP 接線（步驟 4，已完成）

```text
Parse request -> RuleChangeSet
ValidateRuleState(changes) -> 完整唯讀 view
既有 datapath 執行成功 -> Session state.Commit()
manager.Apply(changes, view, resolver) -> 直接更新 policy
```

- manager 從建立 session 開始接收每次成功操作。空 changes 不會從既有 Session 自動重建 policy。
- 沿用 PFCP event loop 序列化，沒有背景 writer。
- 原 datapath 失敗不呼叫 Apply；不新增 QoS rollback 或跨 kernel/BPF transaction。
- `Session.updateQoSPolicies()` 在 state.Commit() 後更新 policy；Apply 本地錯誤輸出 Error log，不改 PFCP 成功回覆，不宣稱跨元件原子提交。
- 完整清理後呼叫 RemoveSession；部分清理只傳已確認移除的 RemovePDRs。
- UPF 啟動時直接建立 manager，由 LocalNode 持有並分享給 Session，無額外模式開關。
- 正式接線使用設定檔的 n3Egress/n6Egress resolver；省略設定時沒有 mapping。Target 先保留出口，Slice/ClassID 未配置時仍保留 MissingTarget；實際 class/BPF 屬於 5-4。
- 非 PFCP target remapping 尚未提供。
- RuleState.Commit 沿用既有 logger，逐筆輸出成功建立／更新的 PDR、FAR、QER、URR、BAR 設定（debug）；直接印出既有 rule，不另外建立日誌結構或組裝 JSON。
- 後續 backend 資源更新若失敗，須明確回報失敗，不宣稱已完成 enforcement；目前不預建補償框架。

## 7. V1-B 的資料面設計與限制

### 7.1 接線

- 通常 UL pacer 掛在實際 N6 egress，DL 掛在實際 N3 egress；介面由明確設定/解析取得。
- DL 的 upfgtp egress 發生在 gtp5g 的 PDR lookup/marking 前，不能當作讀取本次 binding 的掛載點。
- gtp5g 使用 mark 低 24 bits 攜帶 PolicyID；N6/N3 出口 BPF 以 `skb->mark & 0x00ffffff` 查 policy，再設定完整 classid 到 priority。5-2 的 binding TCClassID 固定填 0，出口 BPF 待實作；保留高 8-bit routing 語意。
- 5-1 原始碼檢查發現：UL IPv4 forwarding 可能覆寫 priority；DL 跨 namespace tunnel 傳送可能清除 mark。出口 BPF 需處理 classid 恢復，跨 namespace 尚未驗收，見 [ABI 與路徑檢查](qos_binding_abi_review.md)。
- policy map 的一個 entry 可以指向多個 rate QER；不需要為多 QER 擴增 skb mark 位數或修改目前 PDR binding ABI。
- BPF maps 必須跨適用 egress 共用，否則共享 QER budget 會被拆開。

### 7.2 多 rate QER EDT

eBPF 先讀取整份 policy 的所有有效 rate QER，檢查 missing state/capacity（gate 沿用 gtp5g），再計算同時滿足所有 MBR 的 departure time，最後一致地提交各 rate QER 的 budget/state。單純對每個 QER 各自更新 next_time 後取最大值，仍可能有共享狀態、提前扣帳、排程重合與失敗後殘留 reservation 等問題，必須用模型與實測驗證。

V1 允許優先採較保守的同步設計以確保正確性，例如 session-direction 範圍內序列化 budget reservation；具體 BPF lock/state layout 必須通過目標 kernel verifier，不能巢狀持有多個 bpf_spin_lock，也不能在持鎖區任意呼叫 helpers。跨 session correlation 尚未實作時明確拒絕。

先定義 packet byte accounting（inner IP 或封裝後大小）、burst/queue horizon、既有 timestamp 處理、GSO/offload、drop 是否占用 reservation、更新版本一致性。DL 在 N3 的 skb 長度包含 tunnel overhead，不能直接與 UL inner-IP bytes 混為相同量測口徑。

### 7.2.1 待評估：多 SDF MBR 與共享 Session-AMBR 的 EDT

**狀態：記錄討論細節，尚未選定演算法，不視為已完成的設計決策或 enforcement 能力。** V1-A 可繼續沿用完整 PDR.QERIDs；實作 PR6 前，需決定 reservation、burst、公平性與頻寬利用率的取捨。以下公式是工程候選，不是 3GPP 指定的 EDT 演算法。

#### 適用範圍與政策來源

- SDF 是服務政策所辨識的一群封包，可涵蓋多條 transport connections；不能將 SDF MBR 複製成每條 TCP/UDP connection 的獨立額度。
- PCF 的 `PccRule.flowInfos/appId` 描述匹配條件，`refQosData` 引用 `SmPolicyDecision.qosDecs` 的 `maxbrUl/maxbrDl`。後者是 PCC rule 的 authorized QoS；Session-AMBR 則來自 Session rule 的 `authSessAmbr`。
- non-GBR SDF 可以有額外 MBR；沒有 GBR 保證不代表沒有個別上限。GBR QoS Flow 不加入 Session-AMBR。
- 下例假設封包已透過 PDR 分類到 SDF A 或 B。每個封包使用所選 PDR 的完整 QER 引用，不因其他 PDR 的 filter 也可能匹配就任意累加限制。
- 同一 QoS Flow/QFI 可以包含不同 SDF；QFI 不是所有 rate QER 的唯一 key。SMF 必須先正確表達 SDF QER 的獨立或共享範圍，UPF 不能從 QFI 或相同 MBR 數字猜出缺少的關聯。

#### 範例：三個限制，而非合成一個 MBR

只看同一個 PDU Session 的 DL，速率以 Mbps 表示：

| 限制 | Rate | 共享範圍 |
|---|---:|---|
| SDF A MBR | 20 | 所有屬於 A 的封包 |
| SDF B MBR | 80 | 所有屬於 B 的封包 |
| Session-AMBR | 60 | A、B 與該 session 其他 non-GBR 封包 |

```text
A <= 20 Mbps
B <= 80 Mbps
A + B <= 60 Mbps          # 此例沒有其他 non-GBR 流量

PDR A policy -> [SDF A rate QER, shared AMBR QER]
PDR B policy -> [SDF B rate QER, shared AMBR QER]
```

只送 A 時上限為 20；只送 B 時上限為 60。A=20、B=40 是可行分配，不是 EDT 對 non-GBR 的頻寬保證。不能固定平分 AMBR，也不能把每個 PDR 的速率取 min 後建立互不相關的 pacer。

#### 候選算法：依處理順序保守預約時間

每個 rate QER 保存 `rate_bps` 與 `next_ns`。runtime key 仍為 `(LocalSEID, QERID, Direction)`；同一方向的共享 QER 只有一份狀態，跨 PDR/CPU/適用出口亦然。UL、DL 分開。

以下不累積閒置時的 burst credit，初始 `next_ns=0`，僅適用正值 rate；計費長度與時間單位須一致：

```text
interval_ns(L, R) = ceil(L_bytes * 8 * 1_000_000_000 / R_bps)

對 SDF A 的封包：
    EDT = max(now_ns, next_A, next_AMBR)
    proposed_next_A    = EDT + interval_ns(L, R_A)
    proposed_next_AMBR = EDT + interval_ns(L, R_AMBR)

對 SDF B 的封包：
    EDT = max(now_ns, next_B, next_AMBR)
    proposed_next_B    = EDT + interval_ns(L, R_B)
    proposed_next_AMBR = EDT + interval_ns(L, R_AMBR)
```

一個封包只有一個最終 EDT，多個 rate QER 各自保存狀態；所有適用狀態以同一個最終 EDT 為基準更新。沿用既有 gtp5g gate；pacer 檢查 state、queue horizon 與版本，確認接受預約後，再一致地提交 proposed states。偽碼未處理既有 delivery timestamp；其保留/合成策略仍待決，不能直接覆蓋任意來源的 timestamp。整數乘法溢位、向上取整與目標 BPF 可用運算也需驗證。

#### 時間計算例子

所有封包的計費長度為 1,500 bytes，A/B/AMBR 的 interval 分別是 600/150/200 μs。假設封包都已到達，以 A1、B1、A2、B2 順序預約，為方便計算將 `now` 視為 0：

| 封包 | EDT 計算（μs） | EDT（μs） | 提交後狀態（μs） |
|---|---|---:|---|
| A1 | max(0, 0, 0) | 0 | next_A=600，next_AMBR=200 |
| B1 | max(0, 0, 200) | 200 | next_B=350，next_AMBR=400 |
| A2 | max(0, 600, 400) | 600 | next_A=1200，next_AMBR=800 |
| B2 | max(0, 350, 800) | 800 | next_B=950，next_AMBR=1000 |

這是預約時間表，不是實際 NIC 發送時間，也不是有限時間窗零 burst 的證明。第一個封包可立即發送，驗收仍需明確定義 packetization/burst allowance。

#### 限制與之後要決定的事項

1. **共享時間被推遲、利用率下降。** A2 將 AMBR 推到 800 μs，後處理的 B2 無法回填原本可能使用的 400 μs 空檔。結果依 reservation 順序而變；本算法不保證 work-conserving 或公平性。
2. **更完整的排程候選。** 若需要在 A 尚不能發送時讓 B 使用空檔，應評估具備各 SDF queue 的階層式排程；先選可送 SDF，再分配共享 AMBR。不可直接宣稱單次入隊 EDT 等同這種排程。
3. **EDT 與實際輸出。** EDT 是 earliest departure，不保證精準發送；下游壅塞後，多個已過期 EDT 的封包可能集中送出。需決定是否另需出口整形/burst 控制，並在實際輸出端驗證時間窗限制。
4. **並行一致性。** 多 CPU 不可重複預約同一 `next_AMBR`；SDF 與 AMBR 狀態提交要有一致性協定。可評估 session-direction 序列化，仍須遵守 BPF spin-lock/helper/verifier 限制，不能巢狀鎖多個 map entries。
5. **拒絕與後續丟包。** 在 pacer 因 horizon 等拒絕的封包，不提交時間額度；提交後若被 qdisc/NIC 路徑丟棄，如何處理 reservation 需另訂策略，不能假設可安全回滾已被後續封包依賴的時間。
6. **Accounting/offload。** 固定 inner/outer byte 口徑、GSO 分段策略、時鐘與 timestamp 類型、既有 EDT 合成、更新版本與 burst/horizon 參數。
7. **驗收候選。** 加入上述確定性時間表、多條 connection 共用 SDF cap、多 CPU 共用 AMBR、A2 阻擋 B2 空檔的利用率量測，以及出口停滯後恢復的 burst 測試。這些是後續實作的驗證項目，本次僅更新規劃。

規範與實作參考：

- [TS 29.512 V18.7.1 §4.2.6.6.2](https://www.etsi.org/deliver/etsi_ts/129500_129599/129512/18.07.01_60/ts_129512v180701p.pdf#page=128)：SDF authorized QoS 的 QosData/refQosData 關聯，non-GBR 可包含 maxbrUl/maxbrDl。
- [TS 29.244 V17.10.0 Table 7.5.2.5-1](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/17.10.00_60/ts_129244v171000p.pdf#page=182)：QER MBR 可代表 SDF MBR 或 Session-AMBR，由 PDR 引用集合表達範圍。
- [Linux sch_fq 原始碼（固定 commit）](https://linux.googlesource.com/linux/kernel/git/torvalds/linux/%2B/441c63ff42c4e666304cdd32d23b5fc6bc1ea3cc/net/sched/sch_fq.c)：使用 skb timestamp 的排程實作參考，不據此推論目標 kernel 已完成端到端速率保證。

### 7.3 舊 kernel QoS 的協調

啟用新 pacing 前，必須決定 legacy `qer_with_rate` policer 的 ownership。不能讓它在 eBPF 前只依一個 QER 丟包，再把結果當作新機制的性能。

先調查現有 QoS switch 能否只停用 rate policing 而保留 gate；若不能，需另外做小範圍 kernel 修正。不要透過不下發原本 MBR/GBR 來偷偷改 PFCP 語意。QER-only gate/QFI 更新是否刷新所有關聯 PDR，也是 active 模式前的必測項；有缺陷就列入 kernel companion change。

### 7.4 接線狀態

Manager 隨 PFCP 規則更新，不另設模式開關，日誌由既有 logger 控制。目前完成 policy 同步；binding、TC/BPF 與 EDT 待後續步驟實作。未來 backend 仍須檢查路徑、correlation、QFI ambiguity 與容量，不能悄悄少套一個適用的 QER；不保證 GBR。

## 8. 分批實作與驗收

### 8.1 建立 qos_manager 的執行步驟

1. **模型，已完成：** policy 定義在 internal/rules/qos.go；讀取既有 RuleState，無 Constraint graph。
2. **轉換，已完成：** 使用全部 QERIDs、Source Interface、明確 target mapping 與 QFI 來源/衝突診斷。
3. **直接更新，已完成：** Apply 沿用 RuleChangeSet；只有 policy map 與 PolicyID counter，沒有 Plan/Commit/Abort。
4. **PFCP 接線，已完成：** 啟動時建立 manager，成功套用 rules 後更新 policy；只清除已確認移除的 PDR，沿用 session/association 清理重試，回報本地同步錯誤。
5. **binding 與 backend，待實作：** Set/Clear 編碼、N3/N6 egress、共享 QER 設定/runtime map；不增加本版未要求的 rollback 框架。
   - **5-3 出口設定與 policy 接線已完成：** [設定、測試與封包驗收範圍](qos_egress.md)。本實驗 DL=enp0s8、UL=enp0s9，由設定提供；TC/BPF 掛載與封包計數屬於 5-4。
   - **5-2 已完成程式接線：** [Set/Clear 行為、kernel companion change 與驗證範圍](qos_binding.md)。實際部署、kernel netlink 與封包驗證尚未完成。
   - **5-1 已完成原始碼檢查：** [檢查結果](qos_binding_abi_review.md)。ABI 已有 Set/Clear；UPF 尚未引用本地 library。binding-only 更新沿用 kernel PDR 更新路徑，解析失敗可能刪除原 PDR，須在 5-2 接線前處理；封包保留與 kernel 聯測尚未完成。
6. **EDT 與實測，待實作：** 回看 §7.2.1，決定 reservation、公平性、burst、offload 與並行策略。

## 9. 驗證

已實作測試涵蓋 PDR 更新只影響自己、相同數值仍更新、速率/Gate 更新不讀取或重建 policy、QFI 更新遍歷最終引用、同次新增/更新/刪除、清除最後引用與 QFI、session 隔離、方向、完整 QERIDs、診斷、ID 耗盡與查詢資料隔離。

PFCP 測試使用真實 parser、ValidateRuleState 及 dispatcher，確認 kbps-to-bps、更新保留 GBR/Gate/QFI，缺失引用仍由既有驗證拒絕。第四步另外驗證建立/更新/刪除、disabled、QFI 衝突不拒絕 forwarding、部分清理、association 替換與 SEID 重用。

```sh
go test -race ./internal/rules ./internal/qos_manager ./internal/pfcp ./pkg/factory
go vet ./internal/rules ./internal/qos_manager ./internal/pfcp ./pkg/factory
go build ./...
```

資料面尚待驗證共享 AMBR、SDF caps、跨 CPU/出口、更新不重設 EDT、Gate/QFI refresh、offload 與刪除清理。這些能力不能用控制面單元測試代替。

## 10. 目前可檢查的結果

```text
manager.Policies(LocalSEID)
  PolicyID, PDRID, Direction, Target
  QERIDs=[7,9]
  QFI=5, QFISources=[QER7]
  Diagnostics=[...]

要看 rate/gate：讀取既有 Session/RuleState.QER(7)、QER(9)
```

## 11. 參考依據

- 本地 `go-upf-flowqos/internal/rules/rules.go`、`internal/pfcp/rule_state.go`、`internal/pfcp/rule_apply.go`。
- 本地 `smf` 分支 `fix/ambr-qer-omit-qfi`，commit `0313c25`：optional QFI、兩種 AMBR 建立流程、PFCP builder 與 NGAP；`internal/context/qer_qfi_test.go`、`internal/pfcp/message/qer_qfi_test.go` 為回歸依據。
- 本地 `roundspring2003-gtp5g/src/genl/genl_pdr.c` 的 set_pdr_qfi、qer_with_rate、gate 聚合；`src/gtpu/encap.c` 的 marking 與 policing。
- [3GPP TS 29.244 V17.10.0（ETSI）](https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/17.10.00_60/ts_129244v171000p.pdf)：§5.4.3 gate、Table 7.5.2.5-1 QER/MBR/GBR scope、§8.2.8–8.2.10 rate 編碼與 CorrelationID。既有 PDR/QER 引用據此表達 QoS 的適用範圍；具體 V1 capability 限制是本專案工程選擇，不是標準禁止多 QER。

- [3GPP TS 23.501 V17.10.0（ETSI）](https://www.etsi.org/deliver/etsi_ts/123500_123599/123501/17.10.00_60/ts_123501v171000p.pdf)：§5.7.1.1 QFI 識別 QoS Flow；§5.7.2.6 Session-AMBR 涵蓋該 session 的 non-GBR flows，不適用 GBR flows。共享 AMBR QER 省略 QFI 是本專案分離 rate 與 marking 的配置選擇，不把「任何 AMBR QER 都禁止 QFI」寫成標準要求。
