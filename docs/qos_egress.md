# 5-3：N3/N6 出口與 TC 掛載確認

## 5-3 實作結果（2026-09-16）

使用者已回報完成 iperf 測試，繼續程式實作。出口設定與 policy resolver 已接線；本次未安裝 TC filter、BPF map 或 class，封包層驗收屬於 5-4。

正式部署設定為 `/home/vm1/workspace/free5gc/config/upfcfg.yaml`；本專案另有 [config/upfcfg.yaml](../config/upfcfg.yaml) 可直接使用，兩份設定都包含：

```yaml
qos:
  n3Egress: enp0s8
  n6Egress: enp0s9
```

這是 go-upf-flowqos 的出口設定，不是 mode 開關，也不設定 Linux 路由／NAT。省略 qos 時 manager 仍運作，但沒有出口對應；若提供 qos，N3/N6 都必須填寫。

App 建立時驗證介面存在於目前 namespace，拒絕 loopback 與 upfgtp；允許 N3/N6 共用一張外部網卡。這個檢查不等於驗證 route、qdisc 或鏈路可達。

啟動時建立 resolver 並傳入 NewManager，由 manager 持有。PFCP LocalNode／Session 不保存 resolver，每次只傳入 RuleChangeSet 與 view。PDR Source Interface=Access 對應 UL/N6，Core 對應 DL/N3；其他介面仍 UnsupportedPath。PDR/QER 更新不查 FAR、不新增 rule 副本或 diff。

Policy.Target 現在可先保留已知的 Egress；Slice 空白、ClassID=0 時仍有 MissingTarget，表示尚未完成 class 配置。沒有為了消除診斷而填入假的 slice/class。TC classid 由未來出口 BPF 設定，netlink binding 的 TCClassID 仍為 0。設定在啟動時固定，不提供執行中的 remapping。

已測試 YAML 解碼／缺欄位拒絕、介面驗證、同介面雙向、PFCP 建立後 UL 出口、PDR 改 Source Interface 後 DL 出口、穩定 PolicyID、QER-only 更新保留出口與未知方向處理。

## 連通檢查紀錄

使用者已確認 VM2 的 enp0s8=192.168.56.104/24 為 Host-only，VM1 的 enp0s9 為橋接介面，用於連接實體 iperf server。因此預期 N3/DL 出口是 VM1 enp0s8，N6/UL 出口是 VM1 enp0s9。先前將 enp0s8 當作實體橋接介面的記錄不再適用。

先前本機檢查結果（在使用者回報 iperf 完成之前）：

- 到 gNB 192.168.56.104 的路由以 192.168.56.103 為來源，選 enp0s8。
- enp0s9 目前仍是 192.168.100.3/24，與 DN 192.168.113.21 不在該直連子網。
- 未指定介面的 DN 路由仍走 enp0s3 via 10.0.2.2，N6 橋接路由尚未設定完成。
- `ping -I enp0s9 -c 3 -W 1 192.168.113.21`：3 個封包全部未收到回覆。不能單靠此結果判定 server 離線或 bridge 配置錯誤。
- 指定 `--bind-dev enp0s9 -B 192.168.100.3` 的 iperf3 client 嘗試連接 192.168.113.21:5201，connect timeout=2 秒，結果連線逾時，未開始吞吐量測試。
- 指定介面測試後，鄰居表出現 `192.168.113.21 lladdr 00:0e:c6:87:a7:02 REACHABLE`。有 ARP 鄰居解析證據，但不代表 iperf server 已監聽或 IP 回程可達；仍需確認是否為 server 本身或代理 ARP。

本次實作時重新讀到的未指定介面 DN 路由仍為 enp0s3；保留使用者確認的 enp0s9 部署對應，不擅自修改測試環境。5-4 掛載／驗收時需使用實際 UPF namespace 與封包證明流量經過指定出口。

最終指定拓撲：同一宿主機的兩台 VM 分別跑 free5GC 與 UE/gNB，另一台實體電腦跑 DN/iperf server。

## 使用者確認的實驗拓撲

- 同一宿主機：VM1 執行 free5GC/UPF，VM2 執行 UE/gNB。
- 另一台實體電腦執行 iperf server，DN IP 已確認為 192.168.113.21，透過網路線連接宿主機。
- enp0s8 是兩台 VM 之間的 Host-only 網路；VM1 的 enp0s9 使用 hypervisor bridge，連接宿主機的實體網卡。
- 部署設定 `free5gc/config/upfcfg.yaml` 與本專案 `config/upfcfg.yaml`：PFCP addr/nodeID 為 127.0.0.8，N3 GTP-U addr 為 192.168.56.103，與 `free5gc/config/smfcfg.yaml` 保持一致。DN IP 不可用來綁定 UPF。先前誤改的 `go-upf/config/upfcfg.yaml` 已復原，不作為此實驗設定。
- DNN internet 的 UE 位址池為 10.60.0.0/16、10.61.0.0/16；這些不是 DN server 的位址或 N6 網卡網段。
- VM2 gNB=192.168.56.104，DL 對應 enp0s8；UL 往 DN 對應橋接的 enp0s9。
- 舊 e2e/remote-free5gc 設定屬於不同拓撲，本次沒有拿它推定 VM2 IP，也未修改那些檔案。

```text
同一宿主機：VM2 UE/gNB ── 虛擬網路（N3）── VM1 free5GC/UPF
                                                 │ N6 出口
                                     hypervisor bridge／實體網卡
                                                 │ 網路線
                                     iperf server 192.168.113.21
```

N3 與 N6 可以共用一張介面，也可以分開；需以 VM2 的 IP／虛擬網路與 DN 的實際路由決定。若走直接連線，VM 的 N6 橋接介面需有能到達 DN 的 IP／路由；YAML 的 addr 不會替 Linux 網卡配置位址。回程也需在 server 設 UE pool route，或在 UPF 設 NAT，兩者尚未選定。

## 出口責任

UL 在實際 N6 egress、DL 在實際 N3 egress 掛載 BPF。程式以 mark 低 24 bits 查 policy，設定 priority=classid，再由後續 EDT/qdisc 排程。upfgtp 的 DL egress 位於 gtp5g PDR lookup 前，不是這個出口程式的掛載位置。

Source Interface 只決定 UL/DL，不能單獨決定 Linux egress ifindex。DL 需要到實際 gNB 的路由；UL 需要 UE source、DN destination、解封裝接收介面與完整 skb mark，因為 policy routing 可能使用這些欄位。多 DN／多 gNB／不同 route_id 應逐條路徑確認；一個代表目的地不能證明所有流量出口相同。

## 本機觀察（不是已部署的映射）

| 觀察 | 結果／限制 |
|---|---|
| enp0s3 | 10.0.2.15/24，main table 預設路由 via 10.0.2.2 |
| enp0s8 | 192.168.56.103/24 |
| enp0s9 | 192.168.100.3/24 |
| upfgtp | 目前 namespace 未出現 |
| 命名 network namespaces | `ip netns list` 為空；不代表沒有未命名 container namespace |
| root qdisc | 上述實體介面為 fq_codel，未確認 EDT 所需配置 |
| enp0s3/enp0s8 egress filters | 本次查詢沒有輸出 |

192.168.113.21 已確認是 DN。當前 `ip route get 192.168.113.21` 回傳 `via 10.0.2.2 dev enp0s3 src 10.0.2.15`，不是预期的直接橋接路徑。本次只修正 UPF YAML 綁定位址，沒有修改網卡、route 或 NAT。

探索性查詢 `192.168.56.1 from 192.168.56.103` 選 enp0s8，但未確認該目的地是 gNB；本機到 8.8.8.8 選 enp0s3，但未確認 DN，且這不是帶 UE source/iif 的轉送查詢。因此兩者僅是候選資訊，不可當正式 mapping。

目前 Tailscale 的 `ip rule` 包含 `fwmark 0x80000/0xff0000`；這個 mask 與 FlowQoS 的低 24 bits 有重疊。當 PolicyID 命中對應位元時，可能改變路由規則匹配。本次未更動 Tailscale、mark ABI 或 ID allocator；正式部署需確認 namespace 隔離或路由規則安排，不能只測 PolicyID=1 就宣稱所有 ID 都可用。

## 唯讀檢查工具

```sh
bash testtools/check_qos_egress.sh N3_LOCAL_IPV4 GNB_IPV4 UE_IPV4 DN_IPV4 [UL_MARK] [GTP_DEVICE]
```

預設 UL_MARK=1、GTP_DEVICE=upfgtp。有 MEC route_id 時應傳入包含高 8 bits 的完整 mark；使用實際已配置的 policy ID。工具須在 UPF 所在 network namespace 執行。

工具只執行 route get、link/rule 查詢與 TC show，直接輸出結果，不修改 sysctl、route、qdisc 或 filter。DL 模擬目前 gtp5g 的一般 IPv4 路由查詢；UL 使用 `from UE iif upfgtp mark ...`，不以本機 default route 假裝完成轉送驗證。缺少 GTP device 時退出碼為 2，UL 明確標示 unresolved。路由查詢不會驗證 netfilter 後續改寫、封包實際走向或全部 ECMP 路徑。

## 下一步：5-4

依設定的介面接上 TC egress BPF、policy map 與命中計數，並安排明確的 classid 配置。利用有效 UE IP 與實際 UPF namespace 驗證路徑。ClassID=0／map missing 不能被誤報為已完成 class 分類；EDT 算法仍屬於後續步驟。
