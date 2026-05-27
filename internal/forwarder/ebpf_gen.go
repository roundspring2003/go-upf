package forwarder

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpSmoke ../../ebpf/xdp_prog.c -- -O2 -g -Wall -Werror -I../../ebpf -I/usr/include/x86_64-linux-gnu
