# QoS 與 PFCP 整合

第四步已接入正式 PFCP dispatcher、規則套用及清理流程。第五步的 [FlowQoS binding](qos_binding.md) Set/Clear 也已接線；TC class、BPF map 與 EDT 尚未實作。

## 日誌設定

UPF 啟動時直接建立 qos_manager，所有 PFCP session 共用它，不需要額外的 QoS 模式設定。

Policy 同步不受日誌等級影響。若要查看更新內容，沿用既有 `logger` 區塊，啟用 logger 並將 level 設為 `debug` 或 `trace`；同步失敗仍輸出 Error log。

## 資料流

```text
SMF request
  -> 既有 PFCP parser / RuleChangeSet
  -> ValidateRuleState（合併更新、驗證引用，並呼叫 manager.Prepare 計算 QoS；QFI 衝突時拒絕）
  -> 原 datapath 執行成功
  -> state.Commit()，逐筆輸出成功建立／更新的 rule（debug）
  -> manager.ApplyPrepared(prepared)（使用計算好的 policy）
  -> session datapath Set/Clear binding
```

LocalNode 持有一個 manager；每個 Session 使用同一個 manager，以 Local SEID 區分。所有工作都在既有 PFCP event loop 內完成。

## 看輸出

啟用 debug 日誌時，PDR、FAR、QER、URR、BAR 成功建立或更新後，直接輸出 rule 類型、Local SEID、rule ID 與提交後的完整設定（包含巢狀欄位）。例如 `QER applied: SEID=1 ID=9 rule=...`。不另外建立日誌結構或組裝 JSON。

MBR-only 更新會印出 QER 的新速率，單位為 bps。QFI 更新則會沿著候選 PDR.QERIDs 找出需要刷新摘要的 policy。PDR 改引用只更新自己的 policy。這些 rule 日誌不代表 TC/BPF 已完成 enforcement。

5-3 已接上 [N3/N6 出口設定](qos_egress.md)。支援的 Access/Core PDR 會保存 Target.Egress；Slice/ClassID 尚未配置，仍保留 `MissingTarget`。省略出口設定時 Target 為空。這不是 PFCP request 失敗。未知來源介面會出現 `UnsupportedPath`；多個不同 QFI 會在 forwarding 執行前拒絕，不任選一個 QER。

## 失敗與清理

- 原始 PFCP 驗證、QoS Prepare 或 datapath 執行失敗：不更新 manager、不輸出 rule 成功套用的日誌。
- QoS Apply 本地錯誤：輸出 Error log，原本成功的 PFCP 操作保持成功，不增加 rollback。此時該次 policy 更新未完成，不能把保留的 policy 當成最新結果。
- RemovePDR：只移除該 PDR 的 policy。
- Session/association 清理部分成功：只依 `ApplyResult.Removed.PDRs` 刪除已確認的 policy。其他 policy 保留到既有清理重試確認成功。
- 清理全部完成後才釋放 session/SEID。重用 SEID 不會讀到舊 policy；不同 association 的 session 共用 manager，但資料以 SEID 隔離。

## 已完成的驗證

測試包含編解碼後的 Session Establishment、Modification、Deletion 經過正式 dispatcher；QER-only MBR/QFI 更新、QFI 衝突、無額外設定時自動同步、info 等級下仍更新 policy、datapath/引用驗證失敗、部分清理、association 替換、清理重試及 SEID 重用。

```sh
go test -race ./internal/pfcp ./internal/qos_manager ./internal/rules ./pkg/factory
go vet ./internal/pfcp ./internal/qos_manager ./internal/rules ./pkg/factory
go build ./...
```

整合測試使用 Empty forwarder 或失敗注入 datapath，不需要載入 gtp5g。實際 SMF/UPF 互通與封包上的 mark/priority/EDT 尚未驗收；下一步是 binding 與 backend 接線。
