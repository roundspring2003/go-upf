# 5-2：PDR FlowQoS binding 接線

2026-09-15：Set/Clear 控制面接線已完成，尚未安裝新版 module 或進行 kernel netlink／封包聯測。

2026-10-15 更新：FlowQoS binding 改為版本 2，只傳遞 PolicyID；gtp5g 不再設定 `skb->priority`，出口 eBPF 從 policy map 選擇 TC class。shared mark layout 仍為版本 1。

## 資料流

```text
PFCP rules 成功 → RuleState.Commit
→ qos_manager.Apply：建立／更新 policy
→ Session.updateQoSPolicies
→ sessionDatapath.SetFlowQoS／ClearFlowQoS
→ 既有 Gtp5g client/link → UpdatePDROID
→ kernel PDR 的 flow_qos binding
```

使用同一份 RuleChangeSet 的 AddedPolicies／UpdatedPolicies，不再比較完整 graph。PDR 已刪除時，由 kernel 釋放 binding，UPF 不再對它送 Clear。

支援的 UL/DL policy 下發 PolicyID；Unknown direction 會送 Clear。不同 QER 的 QFI 衝突會在 forwarding 執行前拒絕 PFCP 請求。MissingTarget 不阻止本步驟的 identity marking，因為 class 與出口 BPF 尚未接線；這不是已提供 enforcement 的承諾。MBR-only 更新不改 PolicyID，因此不重送 binding，速率仍由既有 QER 流程處理。

## priority 由出口設定

依本次決定，UL 在 N6 egress BPF、DL 在 N3 egress BPF 依 policy 設定 `skb->priority`。binding 只下發 `PolicyID`；nested attribute 編號 3 保留空號。

gtp5g 將 PolicyID 寫入 mark 低 24 bits，不改寫 priority。出口 BPF 查 policy map 後設定 classid；這個階段的實作不含 EDT。

## 既有規則記錄與錯誤

Set/Clear 只接受本 session 已成功建立的 PDR，OID 固定使用 Local SEID + PDRID。PolicyID 0 與超過 24 bits 的 ID 在送出前拒絕。

Netlink 成功後，將 FlowQoS attr 合併進既有 sessionDatapath.applied.pdrs，保留全部 QER 引用及其他 attr。後續一般 PDR update 與既有 forwarder 恢復流程會保留這份 binding；沒有新增 snapshot 或 rollback 機制。

失敗時只記錄 Error log，保留已成功提交的 PFCP rules／manager policy，以及最後一次確認成功的 applied attr。這表示期望的 policy 與 kernel binding 可能暫時不同；目前没有背景重試，後續該 policy 再被新增／更新時會再次送出。不能用 PFCP accepted 推論 binding 或限速成功。速率更新本身不會觸發 binding 重試。

## Kernel companion change

`roundspring2003-gtp5g/src/genl/genl_pdr.c` 新增 binding-only REPLACE 路徑。只有 LINK、NET_NS_FD、PDR_ID、PDR_SEID、PDR_FLOW_QOS 的訊息可走此路徑。

對已存在的 PDR，直接呼叫 parse_flow_qos，避免經過 pdr_fill 的 FAR/QER/URR、cached QFI 與索引刷新。驗證／配置失敗時不刪除 PDR，也不替換舊 binding；正常 PFCP 欄位更新仍走原本 pdr_fill。PDR_ID 同時改用符合 u16 ABI 的讀取。

此修正僅涵蓋 binding-only 更新，沒有宣稱一般 PDR 更新具有原子性。使用本次 UPF 接線前，需要部署這份 companion module；單純編譯並不會替換執行中的 module。

## 開發依賴與驗證

go.mod 固定引用 `github.com/roundspring2003/go-gtp5gnl v0.0.0-20261015110605-76e10aaacc7c`，對應 binding v2 的 commit `76e10aaacc7c`。不需要 sibling checkout；拉取本 branch 後可以直接下載此依賴。Kernel companion branch 為 [gtp5g/feat/qos-manager-egress](https://github.com/roundspring2003/gtp5g/tree/feat/qos-manager-egress)。

已驗證：

- PFCP／manager／rules race tests；新增 binding 測試涵蓋新增 policy、QER-only 更新、QFI 衝突 Clear、錯誤記錄及刪除後不再 Clear。
- Forwarder 的 FlowQoS／SessionDatapath race tests，涵蓋 SEID/PDRID、Set/Clear、非法 ID、跨 session 隔離、失敗時保留 applied 記錄。
- 相關 Go 套件 vet、UPF build，以及 kernel module 對本機 6.8.0-139 headers 編譯。

尚待驗收：對實際 module 的 Set/Get/Clear、非法 binding 不刪 PDR、一般 PDR update 保留 binding，以及封包 mark。初始建立 PDR 與後續 Set binding 是兩次下發，中間有尚未標記的封包窗口。

5-3 已接上 [出口設定與 resolver](qos_egress.md)；下一步 5-4 接上 policy map 與 BPF 計數／classid 設定，之後才實作 EDT。
