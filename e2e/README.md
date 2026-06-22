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

### Performance validation: RTT and loss

This is the primary experiment. It does not require clock synchronization or
CPU monitoring. On the UPF computer, start a persistent performance endpoint:

```bash
cd ~/workspace/XT-UPF/go-upf
TARGET_PPS=10000 EXPERIMENT_DURATION=30 \
  ./scripts/physical_performance_experiment.sh native
```

On the remote sender computer, run:

```bash
cd ~/workspace/XT-UPF/go-upf
TARGET_PPS=10000 EXPERIMENT_DURATION=30 \
  ./scripts/physical_gtpu_sender.sh
```

After the sender prints its result, return to the UPF terminal and press Enter.
Repeat the same procedure with XDP steering:

```bash
TARGET_PPS=10000 EXPERIMENT_DURATION=30 \
  ./scripts/physical_performance_experiment.sh xdp-steering
```

The sender result is the primary output: sent/received packets, loss percentage,
and RTT minimum/mean/P50/P95/P99/maximum overall and per QFI. UPF-side results
are stored under `experiments/physical-performance-<mode>-*` and contain only
supporting NIC, `upfgtp`, and XDP counters.

For congestion testing, set `CPU_PRESSURE=1` on the UPF command for both native
and XDP groups. Use the same offered rate and run each condition at least five
times. Repeat at increasing rates such as 10k, 20k, 30k, 40k, and 50k pps.

### CPU distribution validation

This is a separate mechanism-validation experiment. It records `mpstat`,
`pidstat`, softirq, IRQ, NIC, `upfgtp`, and XDP counters. Start it on the UPF
computer:

```bash
EXPERIMENT_DURATION=30 ./scripts/physical_cpu_distribution.sh native
```

Run the exact `START_AT=...` sender command printed by the script on the remote
computer. Then repeat with XDP steering:

```bash
EXPERIMENT_DURATION=30 ./scripts/physical_cpu_distribution.sh xdp-steering
```

CPU result directories are named `experiments/physical-cpu-<mode>-*`. Use this
experiment only to demonstrate where native softirq work runs and whether XDP
CPUMAP redirects work to CPUs 16-19; do not use its synchronized window as the
primary RTT/loss result.
