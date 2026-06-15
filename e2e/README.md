# UPF-only E2E topology

## Hosts

- UPF host: `192.168.113.21` (`enx000ec687a702`)
- free5GC control plane and free-ran-ue host: `192.168.113.20`

## UPF host

Start XT-UPF with XDP attached to the real N3 interface:

```bash
cd ~/workspace/XT-UPF/go-upf
./scripts/e2e_upf_start.sh
```

The default mode attaches XDP directly to the physical N3 interface
`enx000ec687a702`.

Verify the attachment:

```bash
sudo ./scripts/ebpf_nic.sh status enx000ec687a702
```

Start a baseline run without XDP:

```bash
E2E_XDP=0 ./scripts/e2e_upf_start.sh
```

Stop XT-UPF:

```bash
./scripts/e2e_upf_stop.sh
```

The stop script also detaches XDP when it was attached by the start script. The
start script uses the already-loaded `gtp5g`, attaches XDP before starting UPF,
and pins the UPF userspace process to CPUs `16-19`. The XDP CPU policy in
`config/upfcfg.yaml` also uses CPUs `16-19` for data-plane processing, so UPF,
XDP softirq/cpumap work, and synthetic congestion compete on the same cores.

If the generated XDP object is missing, generate it before starting:

```bash
./scripts/ebpf_nic.sh gen
```

Environment overrides:

- `E2E_XDP=0|1`: disable or enable XDP; default is `1`.
- `E2E_NIC`: N3 interface; default is `enx000ec687a702`.
- `E2E_UPF_IP`: UPF N3/N4 address; default is `192.168.113.21`.
- `E2E_SMF_IP`: remote control-plane host; default is `192.168.113.20`.
- `UPF_CONFIG`: alternate UPF configuration path.
- `UPF_CPUS`: UPF process affinity; default is `16-19`.

`E2E_XDP=0` also exports `GO_UPF_DISABLE_XDP_QOS=1`, so the UPF skips XDP
map access while keeping normal gtp5g forwarding active.

## Remote control-plane host

Copy these files over the corresponding free5GC configs before starting free5GC:

- `remote-free5gc/amfcfg.yaml`
- `remote-free5gc/smfcfg.yaml`

The remaining NF configs can keep their loopback SBI addresses because those NFs
run on the same remote host. Register the subscriber on that remote free5GC host.

Use `remote-free5gc/free-ran-ue-gnb.yaml` for the gNB configuration. The UE and
gNB are assumed to run on the same remote host, so their internal RAN addresses
remain `127.0.0.1`.

## Physical N3 experiment

Experiments must send GTP-U traffic from the remote host
`192.168.113.20` through the physical N3 interface to
`enx000ec687a702` (`192.168.113.21`). Local veth/network-namespace
traffic scripts have been removed so their results are not mixed with
physical NIC measurements.

### Two-group procedure

Use the same flows, duration, UPF affinity, packet generator, physical cable,
and GRUB CPU-isolation settings for both groups. Both groups force
`rps_cpus=0`; only XDP CPU steering changes:

| Group | XDP | `rps_cpus` | Receive path |
| --- | --- | --- | --- |
| Native UPF | detached | `0` | Single RX queue default Linux/gtp5g path |
| XDP CPU steering | attached | `0` | TEID/QFI policy and CPUMAP to CPUs 16-19 |

This evaluates the practical effect of adding QFI-aware XDP CPU steering to the
native single-RX-queue UPF. It is not an RPS-versus-XDP comparison. CPU 16-19
may remain isolated in GRUB for both groups.

The UPF-side script creates a mock PFCP session with TEID `1`, UE address
`10.60.0.1`, and QFI/class mappings `7/1`, `8/2`, and `9/3`. The remote sender
uses the same values in its GTP-U packets.

Before the first run, either synchronize the `go-upf` repository to the remote
host or copy `bin/gtpuprobe` and `scripts/physical_gtpu_sender.sh` while
preserving the `bin/` and `scripts/` directory layout.

On the UPF computer (`192.168.113.21`), start the native group:

```bash
cd ~/workspace/XT-UPF/go-upf
EXPERIMENT_DURATION=30 ./scripts/physical_upf_experiment.sh native
```

The script prints a `START_AT=...` command. Run that exact command on the remote
computer (`192.168.113.20`) before the synchronized start time:

```bash
cd ~/workspace/XT-UPF/go-upf
START_AT=<printed_epoch> EXPERIMENT_DURATION=30 ./scripts/physical_gtpu_sender.sh
```

Then repeat with XDP steering on the UPF computer:

```bash
EXPERIMENT_DURATION=30 ./scripts/physical_upf_experiment.sh xdp-steering
```

Run the newly printed sender command on the remote computer. Result directories
are named `experiments/physical-native-*` and
`experiments/physical-xdp-steering-*`.

For congested runs, set `CPU_PRESSURE=1` on the UPF-side command for both groups.
Do not set it for only one group. Run each condition at least five times:

```bash
CPU_PRESSURE=1 EXPERIMENT_DURATION=30 ./scripts/physical_upf_experiment.sh native
CPU_PRESSURE=1 EXPERIMENT_DURATION=30 ./scripts/physical_upf_experiment.sh xdp-steering
```

The remote result contains the primary metrics: sent/received packets, loss
percentage, and RTT minimum/mean/P50/P95/P99/maximum, both overall and per QFI.
The UPF result contains supporting CPU, softirq, IRQ, NIC, `upfgtp`, and XDP
counters. Use identical `TARGET_PPS` values for native and XDP runs, for example:

```bash
TARGET_PPS=10000 EXPERIMENT_DURATION=30 ./scripts/physical_upf_experiment.sh native
TARGET_PPS=10000 EXPERIMENT_DURATION=30 ./scripts/physical_upf_experiment.sh xdp-steering
```

Repeat at increasing rates such as 10k, 20k, 30k, 40k, and 50k pps. Keep the
sender result directory with the matching UPF result directory for every run.
