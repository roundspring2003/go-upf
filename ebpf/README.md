# eBPF Smoke Test Scaffold

This directory provides a minimal XDP/TC scaffold to validate helper support:

- `xdp_prog.c`: calls `bpf_xdp_adjust_head`.
- `tc_prog.c`: calls `bpf_skb_adjust_room`.
- `maps.h`: shared structure definitions for upcoming PDR/FAR/QER map work.

Generate Go bindings from `internal/forwarder`:

```bash
go generate ./internal/forwarder
```
