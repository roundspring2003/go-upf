# 5-1：FlowQoS binding ABI 與封包路徑檢查

日期：2026-09-15。此步完成原始碼檢查與現有 ABI 編解碼測試，未下發 binding、載入 BPF、調整 sysctl 或修改網路設定。封包到 TC 的保留情況仍需實測。

後續更新：5-2 已加入 [binding 接線與 kernel binding-only 修正](qos_binding.md)。以下保留 5-1 當時的檢查基線；目前 UPF 已固定引用遠端 library 的 ABI commit，classid 決定由出口 BPF 設定。

## 檢查基線

- UPF：`go-upf-flowqos`，HEAD `3e69ac3` 加上工作區步驟 1–4。
- Kernel module：`roundspring2003-gtp5g`，HEAD `c5fcab0` 加上現有未提交修改；本次檢查的是工作區內容，不代表執行中的 module。
- Netlink library：`go-gtp5gnl`，HEAD `3eefbb0`。
- 主機 kernel：`6.8.0-139-generic`。本機僅有 kernel headers，Linux 通用資料路徑另參照上游 v6.8；尚未逐項核對 Ubuntu patch。
- `go list -m` 確認 UPF 實際使用快取中的 `github.com/free5gc/go-gtp5gnl v1.6.2`，沒有 replace；該版本找不到 FlowQoS 定義。修改本地 library 不會自動影響 UPF。

## ABI 已有的能力

`go-gtp5gnl/attr_pdr.go` 與 kernel `include/genl_pdr.h` 的外層 `PDR_FLOW_QOS` 都是 **14**；13 保留給 PDN type。Nested 欄位如下：

| 屬性編號 | 欄位 | 型別 | 語意 |
|---|---|---|---|
| 1 | Version | u8 | 必須為 1 |
| 2 | PolicyID | u32 | 低 24 bits，最大 0x00ffffff |
| 3 | TCClassID | u32 | 完整 TC classid，與 PolicyID 不同 |
| 4 | Flags | u8 | 1 為有效 binding，0 為清除；其他 bits 不支援 |
| 5 | Generation | u32 | 選填，省略為 0；儲存／回讀用途 |

`NewFlowQoSAttr()` 已負責編碼與基本驗證，`DecodeFlowQoS()` 與 PDR decoder 已支援回讀。Set 要有 Version、PolicyID、TCClassID、Flags；Clear 只需 Version=1、Flags=0。省略整個 FlowQoS attr 會保留原 binding，不等於 Clear。

既有 `UpdatePDROID(client, link, OID{localSEID, uint64(pdrID)}, attrs)` 可攜帶該 attr；送出的命令是 ADD_PDR 加 NLM_F_REPLACE/ACK。識別範圍是 network namespace、gtp link、Local SEID、PDRID，不可只用 PDRID。

Kernel `parse_flow_qos()` 使用 RCU pointer 替換整份 binding；Clear 將 pointer 設為 NULL，舊物件經 kfree_rcu 釋放。PDR 刪除也釋放 binding，因此已刪除的 PDR 不必再送 Clear。

PolicyID=0 通過目前數值驗證，但 shared-mark ABI 定義 0 表示沒有明確 policy；UPF 應沿用 manager 從 1 分配的 ID。TCClassID 目前只驗證為 u32，不檢查 class 是否存在。Generation 沒有出現在封包標記，也沒有 stale-update 比較；不能當成封包版本或資源回收屏障。

## 封包攜帶的資訊

Kernel `src/gtpu/encap.c:69` 的 `gtp5g_apply_packet_policy()` 實際執行：

```text
skb->mark = (route_id << 24) | policy_id
skb->priority = tc_classid
```

更正先前步驟說明：**PolicyID 不在 priority，而在 mark 低 24 bits**。BPF 應用 `mark & 0x00ffffff` 查 policy。`priority` 是交給 TC class 分類的值，不是 QFI 或 5QI priority。

此函式重寫全部 mark 與 priority。沒有有效 binding 時，policy_id/classid 為 0；UL 可以同時攜帶 FAR 的 route_id，正常 DL 呼叫使用 `apply_route_policy=false`，高 8 bits 為 0。這些是 skb 內部 metadata，不是新增到線上封包的 header。

## TC 執行順序

以下是一般 IPv4 Access/Core 轉送路徑；不將 N9、特殊轉送或跨 namespace 視為已驗收。

```text
UL：N3 ingress TC
    → UDP/GTP 接收、PDR lookup
    → 解封裝 → gtp5g 寫 mark/priority（encap.c:1020）
    → netif_rx，以 upfgtp 作為接收介面
    → upfgtp ingress TC → IPv4 forwarding
    → 實際 N6 egress TC → qdisc → 網卡

DL：N6 ingress TC → 路由至 upfgtp
    → upfgtp egress TC → upfgtp ndo_start_xmit
    → PDR lookup → GTP header → gtp5g 寫 mark/priority（encap.c:1160）
    → udp_tunnel_xmit_skb → 外層 IP output
    → 實際 N3 egress TC → qdisc → 網卡
```

因此 DL 的 upfgtp egress 太早，尚未有這次 PDR 分類後的 metadata；應在實際 N3 egress 查 policy。UL 在解封裝後的 upfgtp ingress 已能看到標記，但若要讓封包在實際出口排隊／pacing，仍應接到 N6 egress。

依據：[Linux dev.c](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/core/dev.c) 的 `__dev_queue_xmit()` 在 qdisc／driver 傳送前呼叫 egress hook。Kernel module 的 DL 呼叫鏈為 `dev.c:101` → `encap.c:1197` → `encap.c:1090` 附近的 forwarding → `pktinfo.c:260`。

## 不可直接假定 metadata 一直保留

1. **UL priority 可能被 IPv4 forwarding 覆寫。** [Linux ip_forward.c](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/ipv4/ip_forward.c) 在 `ip_forward_update_priority` 開啟時，依 IP TOS 重新設定 priority。本機讀值為 `net.ipv4.ip_forward_update_priority = 1`。後續可選擇由 N6 TC BPF 用 mark 查 policy 後重新設定 classid，或明確管理 sysctl；本次不修改設定。建議前者，避免依赖整個 namespace 的 priority 設定。
2. **DL 跨 namespace 可能清掉 mark。** Module 將 socket/device 是否跨 namespace 作為 `xnet` 傳入 UDP tunnel 傳送；[iptunnel_xmit](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/ipv4/ip_tunnel_core.c) 會呼叫 [skb_scrub_packet](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/core/skbuff.c)，xnet=true 時清除 mark。同 namespace 通路不會由這個函式清掉 mark；跨 namespace 需另外設計／驗證，不能宣稱已支援。
3. **實際出口上的其他規則仍可能改寫 metadata。** 後續實測需檢查 TC/netfilter、實際 netns 與路由。本次 `ip -br link` 在目前 namespace 沒有看到 upfgtp；不能從 enp0s3/enp0s8/enp0s9 名稱判斷 N3/N6。當前網卡 root qdisc 為 fq_codel，尚未驗收 EDT 所需 qdisc 配置。

## Binding-only 更新的注意事項

目前 kernel 對 UpdatePDR 仍執行完整 `pdr_fill()`，不是獨立無副作用的 binding setter：

- `pdr_fill()` 會重新處理 FAR/QER/URR 關聯、cached QFI、gate、rate pointer、socket 與索引。
- 它先把 `pdr->seid` 設為 0，因此必須使用帶 Local SEID 的 OID API。
- 更重要的是 `gtp5g_genl_add_pdr()` 的既有 REPLACE 路徑，在 `pdr_fill()` 回傳錯誤時會呼叫 `pdr_context_delete(pdr)`。收到 netlink error 不代表舊 PDR 一定還在。
- 雖然 FlowQoS pointer 本身是 RCU 替換，不能據此推論整個 PDR 更新具有原子性。

5-2 前需決定是否先修 kernel 的 binding-only 更新／失敗保留行為，或明確處理錯誤後的 datapath 不一致。這是錯誤語意的缺口，不需要新增使用者已排除的 QoS rollback 框架。本次僅記錄，沒有修改 kernel。

## 5-2 的具體接線工作

1. 讓 UPF 明確引用包含 FlowQoS ABI 的 library 版本；開發時可用專案限定 replace，正式版本則固定可取得的 commit/version。
2. 在既有 forwarder 的 session datapath 邊界增加 Set/Clear binding 能力，重用 client/link/Local SEID。Manager 不另外開 netlink socket。
3. 目前 PolicyID 在 PFCP rules 成功後才分配，初版會是「建立 PDR → Apply policy → binding UpdatePDR」。需承認兩次下發之間會有尚未綁定的封包，不宣稱已提供無間隙 enforcement。
4. 與既有 forwarder applied-rule 記錄保持一致：目前其錯誤恢復可能刪除再建立 PDR；若旁路下發 binding 卻不更新記錄，恢復後可能遺失 binding。沿用既有記錄，不另外新增一套 snapshot。
5. 未建立 BPF map／class 之前，不宣稱有效 binding 能提供限速。後續正式啟用應先準備 policy/map/class，再使 binding 生效；移除時考慮仍在途的封包，Generation 不能取代這個處理。

## 驗證結果與待實測清單

已通過本地 library 既有測試：

```sh
cd /home/vm1/workspace/go-gtp5gnl
go test ./... -run 'Test(FlowQoS|DecodePDRFlowQoS|NewFlowQoS)' -count=1
```

涵蓋 Set/Clear 編解碼、PDR FlowQoS decode 與 encoder 輸入驗證，不是 kernel netlink 聯測。

後續實測：同 session 不同 PDR 綁定、跨 session 同 PDRID 隔離、Set/Replace/Get/Clear、一般 UpdatePDR 保留 binding、刪除 PDR 清理、失敗更新是否保留 PDR；UL/DL 各 hook 的 mark/priority、UL priority 覆寫處理、跨 namespace 行為。實測前先確定正在載入的 module 與所查原始碼一致。
